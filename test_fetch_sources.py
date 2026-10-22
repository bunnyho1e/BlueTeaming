"""Security boundaries of the catalog and non-executing source fetcher."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import fetch_sources as fetcher


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((Path(__file__).parent / 'catalog.json').read_text())

    def test_all_profiles_and_sources_pass_the_same_exclusion_gate(self):
        rows = fetcher.validate_catalog(self.data)
        self.assertTrue(rows)
        self.assertEqual({'github', 'gitlab'}, {r['host'] for r in rows})
        active = {r['id'].lower() for r in rows}
        self.assertTrue(active.isdisjoint({x.lower() for x in self.data['source_review']['excluded_from_catalog']}))

    def test_review_evidence_matches_every_active_pin(self):
        review = json.loads((Path(__file__).parent / 'source-review.json').read_text())
        evidence = {r['id']: r for r in review['repositories']}
        self.assertEqual(set(evidence), {r['id'] for r in self.data['repositories']})
        for row in self.data['repositories']:
            self.assertEqual(evidence[row['id']]['commit'], row['commit'])
            self.assertTrue(evidence[row['id']]['selected_files'])
            self.assertFalse(evidence[row['id']]['executed_upstream'])
        fetcher.validate_review(self.data, review)

    def test_changed_pin_or_missing_review_blocks_retrieval(self):
        review = json.loads((Path(__file__).parent / 'source-review.json').read_text())
        self.data['repositories'][0]['commit'] = '0'*40
        with self.assertRaises(ValueError):
            fetcher.validate_review(self.data, review)
        review['repositories'].pop()
        with self.assertRaises(ValueError):
            fetcher.validate_review(self.data, review)

    def test_incomplete_or_held_review_is_rejected(self):
        original = json.loads((Path(__file__).parent / 'source-review.json').read_text())
        for key, value in [('decision', 'HOLD_ADVISORY'), ('selected_files', []),
                           ('executed_upstream', True), ('code_or_config_files', 0)]:
            review = copy.deepcopy(original)
            review['repositories'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fetcher.validate_review(self.data, review)

    def test_case_changed_duplicate_or_held_identity_is_rejected(self):
        duplicate = copy.deepcopy(self.data['repositories'][0])
        duplicate['id'] = duplicate['id'].upper()
        self.data['repositories'].append(duplicate)
        with self.assertRaises(ValueError):
            fetcher.validate_catalog(self.data)
        self.data['repositories'].pop()
        self.data['source_review']['excluded_from_catalog'].append(duplicate['id'])
        with self.assertRaises(ValueError):
            fetcher.validate_catalog(self.data)

    def test_tampered_pin_url_host_and_path_are_rejected(self):
        for key, value in [('commit', '--upload-pack=payload'), ('commit', 'a'*39),
                           ('clone_url', 'file:///tmp/source'), ('clone_url', 'https://evil.example/repo.git'),
                           ('host', 'unapproved'), ('path', '../outside'),
                           ('category', '../outside'), ('slug', 'owner/../outside')]:
            data = copy.deepcopy(self.data)
            data['repositories'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                fetcher.validate_catalog(data)

    def test_inactive_profile_member_blocks_all_selections(self):
        self.data['profiles']['starter'].append('github:unreviewed/source')
        with self.assertRaises(ValueError):
            fetcher.validate_catalog(self.data)

    def test_lab_sources_are_not_in_the_starter_profile(self):
        rows = {r['id']: r for r in self.data['repositories']}
        for identity in self.data['profiles']['starter']:
            self.assertNotIn(rows[identity]['usage_class'], {'ISOLATED_LAB', 'MALWARE_ANALYSIS_ISOLATED'})


class FetchSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(fetcher, 'ROOT', self.root)
        self.root_patch.start()
        self.row = {'id': 'github:example/project', 'host': 'github', 'slug': 'example/project',
                    'category': 'detection-engineering', 'path': 'tools/detection-engineering/github/example--project',
                    'commit': 'a'*40, 'clone_url': 'https://github.com/example/project.git'}

    def tearDown(self):
        self.root_patch.stop()
        self.temp.cleanup()

    def test_destination_symlink_is_rejected_before_git(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'tools').symlink_to(outside, target_is_directory=True)
        with patch.object(fetcher, 'git') as git, self.assertRaises(ValueError):
            fetcher.fetch(self.row)
        git.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_external_git_directory_is_rejected(self):
        target = self.root / self.row['path']
        target.mkdir(parents=True)
        (target / '.git').write_text('gitdir: /outside')
        with patch.object(fetcher, 'git') as git, self.assertRaises(ValueError):
            fetcher.fetch(self.row)
        git.assert_not_called()

    def test_nonempty_destination_is_preserved(self):
        target = self.root / self.row['path']
        target.mkdir(parents=True)
        (target / 'local.txt').write_text('keep')
        with self.assertRaises(ValueError):
            fetcher.fetch(self.row)
        self.assertEqual((target / 'local.txt').read_text(), 'keep')

    def test_dangerous_git_filters_and_includes_are_rejected(self):
        target = self.root / 'repo'
        target.mkdir()
        fetcher.git('init', cwd=target, capture=True)
        for key in ['filter.payload.smudge', 'include.path', 'core.worktree']:
            fetcher.git('config', '--local', key, 'unreviewed-value', cwd=target, capture=True)
            with self.subTest(key=key), self.assertRaises(ValueError):
                fetcher.check_local_git_config(target)
            fetcher.git('config', '--file', str(target / '.git' / 'config'), '--unset', key,
                        cwd=self.root, capture=True)

    def test_inherited_git_overrides_are_removed_and_hooks_disabled(self):
        with patch.dict(os.environ, {'GIT_DIR': '/outside', 'GIT_WORK_TREE': '/outside',
                                     'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.worktree'}):
            with patch.object(fetcher.subprocess, 'run') as run:
                fetcher.git('status', cwd=self.root)
        env = run.call_args.kwargs['env']
        for key in ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0']:
            self.assertNotIn(key, env)
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], os.devnull)
        self.assertIn('core.hooksPath=/dev/null', run.call_args.args[0])
        self.assertIn('protocol.allow=never', run.call_args.args[0])

    def test_existing_origin_mismatch_is_rejected_before_network_fetch(self):
        target = self.root / self.row['path']
        target.mkdir(parents=True)
        fetcher.git('init', cwd=target, capture=True)
        fetcher.git('remote', 'add', 'origin', 'https://github.com/wrong/source.git', cwd=target, capture=True)
        with self.assertRaisesRegex(ValueError, 'origin'):
            fetcher.fetch(self.row)


if __name__ == '__main__':
    unittest.main()
