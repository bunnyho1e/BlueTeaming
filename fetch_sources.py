#!/usr/bin/env python3
"""Fetch selected, pinned source trees. Never install or execute upstream code."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
HOSTS = {'github': 'https://github.com/', 'gitlab': 'https://gitlab.com/'}
GIT_OPTIONS = ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
               '-c', 'http.sslVerify=true', '-c', 'submodule.recurse=false',
               '-c', 'credential.helper=', '-c', 'init.templateDir=']


def git(*args, cwd, capture=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_NOSYSTEM='1', GIT_LFS_SKIP_SMUDGE='1')
    return subprocess.run(['git', *GIT_OPTIONS, *args], cwd=cwd, env=env,
                          check=True, text=True, capture_output=capture, timeout=300)


def validate_catalog(data):
    categories = [c['id'] for c in data['categories']]
    if len(set(categories)) != len(categories) or any(
            not re.fullmatch(r'[a-z][a-z0-9-]*', c) for c in categories):
        raise ValueError('Invalid or duplicate category')
    excluded = {i.lower() for i in data['source_review']['excluded_from_catalog']}
    seen, paths = set(), set()
    rows = data['repositories']
    for row in rows:
        identity = row['id'].lower()
        if identity in seen or identity in excluded:
            raise ValueError('Duplicate or excluded source: ' + row['id'])
        parts = row['slug'].split('/')
        if len(parts) < 2 or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', p)
                                 or p in {'.', '..'} for p in parts):
            raise ValueError('Invalid source identity')
        host = HOSTS.get(row['host'])
        if (not host or row['id'] != row['host'] + ':' + row['slug']
                or row['clone_url'] != host + row['slug'] + '.git'
                or not re.fullmatch(r'[0-9a-f]{40}', row['commit'])):
            raise ValueError('Unapproved source host, URL, or commit')
        expected = 'tools/' + row['category'] + '/' + row['host'] + '/' + row['slug'].replace('/', '--')
        if (row['category'] not in categories or row['path'] != expected
                or row['path'].lower() in paths):
            raise ValueError('Invalid or colliding source destination')
        seen.add(identity)
        paths.add(row['path'].lower())
    active = {r['id'] for r in rows}
    for ids in data['profiles'].values():
        if len(ids) != len(set(ids)) or not set(ids) <= active:
            raise ValueError('Profile contains duplicate or unavailable sources')
    return rows


def validate_review(data, review):
    observations = review['repositories']
    indexed = {r['id']: r for r in observations}
    active = {r['id'] for r in data['repositories']}
    if len(indexed) != len(observations) or set(indexed) != active:
        raise ValueError('Review evidence does not match the active source identities')
    for row in data['repositories']:
        record = indexed[row['id']]
        if (record['commit'] != row['commit'] or record['decision'] != 'INCLUDE_SOURCE_ONLY'
                or record['executed_upstream'] is not False
                or record['osv']['status'] != 'NO_RECORD_RETURNED'
                or record['code_or_config_files'] < 1):
            raise ValueError('Missing, outdated, or held source review: ' + row['id'])
        files = record['selected_files']
        if not files or any(not re.fullmatch(r'[0-9a-f]{64}', f['sha256'])
                            or not isinstance(f['bytes'], int) or f['bytes'] < 0 for f in files):
            raise ValueError('Invalid inspected-source fingerprints: ' + row['id'])


def safe_target(row):
    target = ROOT / row['path']
    if ROOT.resolve() not in target.resolve().parents:
        raise ValueError('Source destination escapes workspace')
    for part in (target, *target.parents):
        if part == ROOT:
            break
        if part.is_symlink():
            raise ValueError('Symlink in source destination')
    return target


def check_local_git_config(target):
    result = git('config', '--no-includes', '--file', str(target / '.git' / 'config'),
                 '--null', '--list', cwd=ROOT, capture=True)
    allowed = {'core.repositoryformatversion', 'core.filemode', 'core.bare',
               'core.logallrefupdates', 'core.ignorecase', 'core.precomposeunicode',
               'remote.origin.url', 'remote.origin.fetch'}
    for entry in result.stdout.split('\0'):
        if entry:
            key = entry.split('\n', 1)[0].lower()
            if key not in allowed and not re.fullmatch(r'branch\..+\.(remote|merge)', key):
                raise ValueError('Unreviewed local Git setting: ' + key)


def fetch(row):
    target = safe_target(row)
    target.parent.mkdir(parents=True, exist_ok=True)
    dotgit = target / '.git'
    if dotgit.is_symlink() or (dotgit.exists() and not dotgit.is_dir()):
        raise ValueError('Refusing external Git directory')
    if not dotgit.exists():
        if target.exists() and any(target.iterdir()):
            raise ValueError('Refusing to initialize a nonempty directory')
        target.mkdir(exist_ok=True)
        git('init', cwd=target, capture=True)
        git('remote', 'add', 'origin', row['clone_url'], cwd=target, capture=True)
    check_local_git_config(target)
    origin = git('config', '--local', '--get', 'remote.origin.url', cwd=target, capture=True).stdout.strip()
    if origin != row['clone_url']:
        raise ValueError('Existing origin does not match the reviewed source')
    git('fetch', '--no-tags', '--depth', '1', 'origin', row['commit'], cwd=target, capture=True)
    git('checkout', '--detach', row['commit'], cwd=target, capture=True)
    actual = git('rev-parse', 'HEAD', cwd=target, capture=True).stdout.strip()
    if actual != row['commit']:
        raise ValueError('Fetched commit does not match the reviewed pin')
    return row['id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--all', action='store_true')
    selection.add_argument('--profile')
    selection.add_argument('--category')
    selection.add_argument('--repo')
    parser.add_argument('--jobs', type=int, choices=range(1, 17), default=4)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    data = json.loads((ROOT / 'catalog.json').read_text(encoding='utf-8'))
    rows = validate_catalog(data)
    validate_review(data, json.loads((ROOT / 'source-review.json').read_text(encoding='utf-8')))
    if args.profile:
        if args.profile not in data['profiles']:
            parser.error('Unknown profile. Available: ' + ', '.join(data['profiles']))
        wanted = set(data['profiles'][args.profile])
        rows = [r for r in rows if r['id'] in wanted]
    elif args.category:
        rows = [r for r in rows if r['category'] == args.category]
    elif args.repo:
        rows = [r for r in rows if r['id'] == args.repo]
    if not rows:
        parser.error('No active source matches this selection')
    if args.dry_run:
        for row in rows:
            print(row['id'] + '\t' + row['commit'])
    else:
        failed = []
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(fetch, row): row['id'] for row in rows}
            for future in as_completed(futures):
                try:
                    print('Fetched ' + future.result(), flush=True)
                except (ValueError, OSError, subprocess.SubprocessError) as error:
                    failed.append(futures[future])
                    print('Failed ' + futures[future] + ': ' + str(error), flush=True)
        if failed:
            parser.exit(1, str(len(failed)) + ' source retrievals failed. Existing source data was preserved.\n')
    print(str(len(rows)) + ' active source projects selected.')


if __name__ == '__main__':
    main()
