#!/usr/bin/env python3
"""Read bounded upstream source snapshots without installing or executing them."""
import concurrent.futures as cf
import datetime as dt
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import time
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'audit-output'
OUT.mkdir(exist_ok=True)
MAX_ARCHIVE=24*1024*1024
MAX_EXPANDED=128*1024*1024
MAX_FILE=1024*1024
SUFFIXES={'.py','.sh','.ps1','.psm1','.go','.rs','.js','.ts','.c','.cc','.cpp','.h','.rb','.pl','.pm','.cs','.java','.json','.toml','.yml','.yaml','.xml','.cfg','.conf','.ini','.service','.rules','.yar','.yara','.sls','.lua','.bat','.cmd','.gradle','.groovy','.j2','.jinja','.csproj','.sln'}
MANIFESTS={'Makefile','Dockerfile','Gemfile','configure','configure.ac','CMakeLists.txt','meson.build','setup.py','setup.cfg','pyproject.toml','package.json','go.mod','Cargo.toml','build.rs'}
PATTERNS={
 'remote_installer_pipeline':re.compile(r'(?:curl|wget)[^\n]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b',re.I),
 'encoded_execution':re.compile(r'(?:exec|eval)\s*\([^\n]{0,140}(?:base64|b64decode|fromhex)|base64\s+(?:-d|--decode)[^\n]{0,100}\|\s*(?:ba)?sh',re.I),
 'credential_store_reference':re.compile(r'\.aws/credentials|\.ssh/id_rsa|\.config/gcloud|Login Data|wallet\.dat|/etc/shadow|\.kube/config',re.I),
 'external_webhook_reference':re.compile(r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw',re.I),
 'miner_reference':re.compile(r'\b(?:xmrig|stratum\+tcp|cryptonight)\b',re.I),
 'persistence_reference':re.compile(r'/etc/cron|\.bashrc|\.zshrc|authorized_keys|systemctl\s+enable',re.I),
 'security_control_change':re.compile(r'Set-MpPreference[^\n]{0,200}(?:Disable|Exclusion)|DisableRealtimeMonitoring|setenforce\s+0|systemctl\s+(?:stop|disable)\s+(?:auditd|firewalld|ufw)',re.I),
}

def now():return dt.datetime.now(dt.timezone.utc).isoformat()

def request(url,limit=MAX_ARCHIVE,data=None,timeout=12):
    headers={'User-Agent':'BlueTeaming-static-source-screen/1.0'}
    if data is not None:headers['Content-Type']='application/json'
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers,data=data),timeout=timeout) as r:
        if not r.geturl().startswith('https://'):raise ValueError('Non-HTTPS redirect')
        if int(r.headers.get('Content-Length','0'))>limit:raise ValueError('Response exceeds review bound')
        body=r.read(limit+1)
        if len(body)>limit:raise ValueError('Response exceeds review bound')
        return body

def jreq(url):return json.loads(request(url,limit=8*1024*1024))


def scan(record,path,raw):
    p=PurePosixPath(path)
    if p.suffix.lower() not in SUFFIXES and p.name not in MANIFESTS and not p.name.lower().startswith(('readme','license','copying','security')):return
    if b'\0' in raw[:4096]:return
    record['scanned_text_files']+=1;record['scanned_text_bytes']+=len(raw)
    if p.suffix.lower() in SUFFIXES or p.name in MANIFESTS:record['code_or_config_files']+=1
    for kind,pat in PATTERNS.items():
        for no,line in enumerate(raw.decode('utf-8',errors='replace').splitlines(),1):
            if pat.search(line):
                if len(record['indicators'])<65:record['indicators'].append({'kind':kind,'path':path,'line':no,'excerpt':line[:280]})
                record['indicator_counts'][kind]=record['indicator_counts'].get(kind,0)+1
                break

def score(path):
    p=PurePosixPath(path);n=p.name.lower();d=len(p.parts)
    if d==1 and n.startswith(('license','copying')):return 100
    if d==1 and n.startswith('readme'):return 98
    if d==1 and p.name in MANIFESTS:return 96
    if d==1 and n=='security.md':return 95
    if d<4 and re.match(r'^(main|__main__|cli|app|agent|server|install|setup|build)\.',n):return 88-d
    if d<3 and p.name in MANIFESTS:return 80-d
    if d<4 and p.suffix.lower() in SUFFIXES and not any(x in path.lower() for x in ['test','vendor','fixture','third_party','node_modules']):return 40-d
    return 0

def inspect(r):
    s,m=r['candidate'],r['metadata'];slug=m['full_name'];host=s['host'];pin=r['commit']
    directory=OUT/(host+'--'+slug.replace('/','--'));directory.mkdir(exist_ok=True)
    output=directory/'inspection.json'
    if output.exists():
        cached=json.loads(output.read_text())
        if cached.get('commit')==pin and cached.get('decision')=='SCREEN_COMPLETE':return cached
    rec={'id':host+':'+slug,'commit':pin,'checked_at':now(),'scanned_text_files':0,'scanned_text_bytes':0,'code_or_config_files':0,
         'indicators':[],'indicator_counts':{},'selected_files':[],'executed_upstream':False}
    selected=[];start=time.monotonic()
    try:
        if host=='github' and m.get('size',0)>90000:raise ValueError('Large source tree: selected-file inspection')
        url=f'https://codeload.github.com/{slug}/tar.gz/{pin}' if host=='github' else f'https://gitlab.com/api/v4/projects/{r["gitlab_project_id"]}/repository/archive.tar.gz?sha={pin}'
        data=request(url)
        rec['archive']={'url':url,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        total=0;members=0
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tf:
            for f in tf:
                members+=1
                if members>90000 or time.monotonic()-start>60:raise ValueError('Source work bound reached')
                p=PurePosixPath(f.name)
                if p.is_absolute() or '..' in p.parts:raise ValueError('Unsafe archive path')
                path='/'.join(p.parts[1:])
                if not path or not f.isfile() or f.size>MAX_FILE:continue
                total+=f.size
                if total>MAX_EXPANDED:raise ValueError('Expanded source bound reached')
                pp=PurePosixPath(path)
                if pp.suffix.lower() not in SUFFIXES and pp.name not in MANIFESTS and score(path)==0:continue
                raw=tf.extractfile(f).read();scan(rec,path,raw)
                if score(path):selected=sorted(selected+[(score(path),path,raw)],key=lambda x:(-x[0],x[1]))[:16]
        rec['archive']['members']=members;rec['inspection_mode']='BOUNDED_SNAPSHOT'
    except Exception as e:
        rec['snapshot_limit_or_error']=str(e)[:250];rec['inspection_mode']='SELECTED_FILES_ONLY'
        if not selected:
            paths=r.get('selected_paths') or [{'path':p} for p in ['README.md','README.rst','README','LICENSE','LICENSE.md','COPYING','SECURITY.md','pyproject.toml','setup.py','package.json','Cargo.toml','go.mod','Makefile','Dockerfile']]
            for item in paths[:20]:
                if time.monotonic()-start>65:break
                path=item['path']
                url=f'https://raw.githubusercontent.com/{slug}/{pin}/{path}' if host=='github' else f'https://gitlab.com/api/v4/projects/{r["gitlab_project_id"]}/repository/files/{urllib.parse.quote(path,safe="")}/raw?ref={pin}'
                try:
                    raw=request(url,limit=MAX_FILE,timeout=7)
                    if item.get('blob_sha') and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=item['blob_sha']:raise ValueError('Git blob digest mismatch')
                    if item.get('sha256') and hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('Source digest mismatch')
                    scan(rec,path,raw);selected.append((score(path),path,raw))
                except Exception as failure:
                    if 'digest mismatch' in str(failure):rec['integrity_error']=str(failure)
    for priority,path,raw in sorted(selected,key=lambda x:(-x[0],x[1]))[:16]:
        (directory/('file--'+path.replace('/','--'))).write_bytes(raw)
        rec['selected_files'].append({'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
          'url':f'https://github.com/{slug}/blob/{pin}/{path}' if host=='github' else f'https://gitlab.com/{slug}/-/blob/{pin}/{path}'})
    minimum=2 if rec['inspection_mode']=='BOUNDED_SNAPSHOT' else 3
    rec['decision']='SCREEN_COMPLETE' if rec['scanned_text_files']>=minimum and rec['code_or_config_files']>=1 and not rec.get('integrity_error') else 'HOLD_INSUFFICIENT_SOURCE'
    output.write_text(json.dumps(rec,indent=2)+'\n')
    print(rec['id'],rec['decision'],rec['inspection_mode'],'files='+str(rec['scanned_text_files']),'flags='+str(len(rec['indicators'])),flush=True)
    return rec

def main():
    import argparse
    from fetch_sources import validate_catalog
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--all',action='store_true')
    group.add_argument('--repo')
    parser.add_argument('--jobs',type=int,choices=range(1,13),default=4)
    args=parser.parse_args()
    catalog=json.loads((ROOT/'catalog.json').read_text())
    rows=validate_catalog(catalog)
    if args.repo:rows=[r for r in rows if r['id']==args.repo]
    if not rows:parser.error('No active source matches this selection')
    previous=json.loads((ROOT/'source-review.json').read_text())
    observations={r['id']:r for r in previous['repositories']}
    pins=[]
    for row in rows:
        old=observations[row['id']]
        m=old['provider_metadata']
        entry={'candidate':{'host':row['host'],'slug':row['slug']},'commit':row['commit'],
               'metadata':{'full_name':row['slug'],'size':100000 if old['inspection_mode']=='SELECTED_FILES_ONLY' else 0},
               'selected_paths':[{'path':f['path'],'sha256':f['sha256']} if old['commit']==row['commit'] else {'path':f['path']} for f in old['selected_files']]}
        if row['host']=='gitlab':entry['gitlab_project_id']=row['gitlab_project_id']
        pins.append(entry)
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:records=list(pool.map(inspect,pins))
    (OUT/'inspection-summary.json').write_text(json.dumps(records,indent=2)+'\n')
    queries=[{'commit':r['commit']} for r in rows]
    batch={'queried_at':now(),'queries':queries,'results':[]}
    try:
        for i in range(0,len(queries),100):
            response=json.loads(request('https://api.osv.dev/v1/querybatch',limit=8*1024*1024,
                data=json.dumps({'queries':queries[i:i+100]}).encode(),timeout=25))
            if len(response.get('results',[]))!=len(queries[i:i+100]):raise ValueError('Incomplete advisory results')
            batch['results']+=response['results']
    except Exception as error:batch['error']=str(error)
    (OUT/'osv-batch.json').write_text(json.dumps(batch,indent=2)+'\n')
    print('Wrote source and advisory observations to audit-output/. Catalog pins and inclusion decisions were not changed.')

if __name__=='__main__':main()
