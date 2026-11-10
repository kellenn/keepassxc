#!/usr/bin/env python3
# Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
# SPDX-License-Identifier: GPL-2.0-or-later
"""Standalone deployment SBOM regression tests (Python + spdx-tools)."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('generate_sbom', ROOT / 'utils/generate-sbom.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RELEASE_SPEC = importlib.util.spec_from_file_location('release_tool', ROOT / 'release-tool.py')
RELEASE = importlib.util.module_from_spec(RELEASE_SPEC)
RELEASE_SPEC.loader.exec_module(RELEASE)


def document():
    return {'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT', 'dataLicense': 'CC0-1.0',
            'name': 'fixture', 'documentNamespace': 'https://example.org/fixture',
            'creationInfo': {'created': '2026-01-01T00:00:00Z', 'creators': ['Tool: test']},
            'packages': [], 'files': [], 'relationships': []}


def package(name, identifier=None):
    return {'SPDXID': identifier or f'SPDXRef-{name}', 'name': name, 'versionInfo': '1.2.3',
            'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
            'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION'}


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sbom test ')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.deploy = self.directory / 'deploy'
        self.deploy.mkdir()
        self.sbom = MODULE.DeploymentSbom(document(), self.deploy, '2.8.0')

    def deploy_binary(self, name, magic=b'\x7fELF'):
        path = self.deploy / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(magic + b'example deployed bytes')
        return path

    def collect_deployed_files(self):
        self.sbom.collect_deployed_files(self.directory / 'output.spdx.json')

    def test_inventory_platforms_and_signed_bytes(self):
        for name, magic in [('keepassxc.exe', b'MZ\0\0'), ('QtCore.framework/QtCore', b'\xcf\xfa\xed\xfe'),
                            ('libQt6Core.so.6', b'\x7fELF')]:
            path = self.deploy_binary(name, magic)
            path.write_bytes(path.read_bytes() + b'signature')
        self.collect_deployed_files()
        self.assertEqual(len(self.sbom.binary_files), 3)
        for entry in self.sbom.document['files']:
            path = self.deploy / entry['fileName']
            self.assertIn({'algorithm': 'SHA256', 'checksumValue': hashlib.sha256(path.read_bytes()).hexdigest()},
                          entry['checksums'])
        self.sbom.finalize_document()

    def test_assets_are_excluded_including_syft_file_records(self):
        self.deploy_binary('usr/lib/libexample.so.1')
        (self.deploy / 'AppRun').write_text('#!/bin/sh\nexec usr/bin/keepassxc\n')
        for name in ('share/translations/qt_de.qm', 'share/icons/example.png',
                     'share/applications/example.desktop', 'share/doc/manual.html',
                     'usr/share/doc/qt6-wayland/copyright', 'COPYING'):
            path = self.deploy / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'asset content')
        self.sbom.document['files'] = [{'SPDXID': 'SPDXRef-asset', 'fileName': './share/icons/example.png'}]
        self.sbom.document['files'][0]['licenseConcluded'] = 'LicenseRef-asset'
        self.sbom.document['hasExtractedLicensingInfos'] = [
            {'licenseId': 'LicenseRef-asset', 'extractedText': 'Asset license'}]
        self.sbom.root['hasFiles'] = ['SPDXRef-asset']
        self.sbom.add_relationship(self.sbom.root_id, 'CONTAINS', 'SPDXRef-asset')
        self.sbom.add_relationship('SPDXRef-asset', 'OTHER', self.sbom.root_id)
        self.collect_deployed_files()
        exclusions = MODULE.syft_asset_exclusions(self.deploy)
        self.assertIn('./share/icons/example.png', exclusions)
        self.assertIn('./COPYING', exclusions)
        self.assertIn('./usr/share/doc/qt6-wayland/copyright', exclusions)
        self.assertNotIn('./usr/lib/libexample.so.1', exclusions)
        self.assertNotIn('./AppRun', exclusions)
        self.assertNotIn('./share/doc/manual.html', exclusions)
        self.sbom.finalize_document()
        self.assertEqual({file['fileName'] for file in self.sbom.document['files']},
                         {'usr/lib/libexample.so.1', 'AppRun', 'share/doc/manual.html'})
        documentation = next(file for file in self.sbom.document['files'] if file['fileName'].endswith('.html'))
        self.assertEqual(documentation['licenseConcluded'], self.sbom.root['licenseDeclared'])
        self.assertEqual(documentation['copyrightText'], self.sbom.root['copyrightText'])
        self.assertEqual(documentation['fileTypes'], ['DOCUMENTATION'])
        self.assertIn({'spdxElementId': self.sbom.root_id, 'relationshipType': 'CONTAINS',
                       'relatedSpdxElement': documentation['SPDXID']}, self.sbom.document['relationships'])
        self.assertEqual(self.sbom.root['versionInfo'], '2.8.0')
        self.assertFalse(any('SPDXRef-asset' in rel.values() for rel in self.sbom.document['relationships']))
        self.assertNotIn('SPDXRef-asset', self.sbom.root['hasFiles'])
        self.assertEqual(self.sbom.document['hasExtractedLicensingInfos'], [])

    def test_project_license_does_not_apply_to_bundled_dependencies(self):
        for name in ('usr/bin/keepassxc', 'usr/lib/libQt6Network.so.6', 'Qt6Core.dll',
                     'QtCore.framework/QtCore', 'plugins/platforms/libqxcb.so'):
            self.deploy_binary(name)
        self.collect_deployed_files()
        files = {f['fileName']: f for f in self.sbom.document['files']}
        self.assertEqual(files['./usr/bin/keepassxc']['licenseConcluded'], 'GPL-2.0-or-later')
        self.assertIn('keepassxc', self.sbom.accounted)
        self.assertNotIn('libqt6network.so.6', self.sbom.accounted)
        for name, entry in files.items():
            if name != './usr/bin/keepassxc':
                self.assertEqual(entry['licenseConcluded'], 'NOASSERTION')
                self.assertEqual(entry['copyrightText'], 'NOASSERTION')
        self.sbom.finalize_document()

    def test_inventory_preserves_supplier_file_license(self):
        name = 'usr/lib/libQt6Network.so.6'
        self.deploy_binary(name)
        self.sbom.document['files'] = [{'SPDXID': 'SPDXRef-qt-network',
                                      'fileName': './usr//lib/../lib/./libQt6Network.so.6',
                                      'licenseConcluded': 'LGPL-3.0-only',
                                      'copyrightText': 'Qt contributors'}]
        self.collect_deployed_files()
        entry = self.sbom.document['files'][0]
        self.assertEqual(entry['licenseConcluded'], 'LGPL-3.0-only')
        self.assertEqual(entry['copyrightText'], 'Qt contributors')
        self.sbom.finalize_document()
        self.assertEqual(entry['fileName'], name)
        self.assertEqual(len(self.sbom.document['files']), 1)

    def test_canonical_filename_resolves_symlinks_within_deployment(self):
        target = self.deploy_binary('lib/libexample.so.1.2')
        alias = target.with_name('libexample.so.1')
        try:
            alias.symlink_to(target.name)
        except OSError:
            self.skipTest('Symlink creation unavailable')
        self.assertEqual(self.sbom.resolve_deployed_path('./lib/../lib/libexample.so.1'),
                         'lib/libexample.so.1.2')
        with self.assertRaises(ValueError):
            self.sbom.resolve_deployed_path('../outside-deployment')

    def test_syft_native_metadata_preserves_binary_evidence(self):
        for name, metadata in [('example.dll', {'legalCopyright': 'DLL supplier'}),
                               ('Example.framework/Example', {'copyright': 'Framework supplier'})]:
            with self.subTest(name=name):
                self.deploy_binary(name)
                artifact_id = hashlib.sha256(name.encode()).hexdigest()[:16]
                component = package(name, 'SPDXRef-Package-generic-' + artifact_id)
                component['licenseDeclared'] = 'MIT'
                self.sbom.document['packages'].append(component)
                self.collect_deployed_files()
                self.sbom.apply_syft_metadata({'artifacts': [{
                    'id': artifact_id, 'version': '1.2.3', 'metadata': metadata,
                    'locations': [{'path': '/' + name}]}]})
                self.assertEqual(component['licenseDeclared'], 'MIT')
                self.assertEqual(component['copyrightText'], next(iter(metadata.values())))
                self.assertIn(Path(name).name.lower(), self.sbom.accounted)
        self.sbom.finalize_document()

    def test_linux_build_id_handles_modified_deployment(self):
        deployed = self.deploy_binary('libexample.so.1')
        original = self.directory / 'original.so'
        original.write_bytes(deployed.read_bytes() + b'different RPATH')
        with patch.object(MODULE, 'query_local_command', return_value='Build ID: 123abc'):
            self.assertTrue(MODULE.matches_binary(deployed, original))
        with patch.object(MODULE, 'query_local_command', side_effect=['Build ID: 123abc', 'Build ID: other']):
            self.assertFalse(MODULE.matches_binary(deployed, original))

    def test_distro_scan_excludes_unmatched_packages(self):
        self.deploy_binary('libexample.so.1')
        self.collect_deployed_files()
        source = document()
        source['packages'] = [package('example'), package('unused')]
        for matches in (False, True):
            with patch.object(MODULE.sys, 'platform', 'linux'), \
                    patch.object(MODULE.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
                    patch.object(MODULE, 'query_local_command', return_value='example: /lib/libexample.so.1'), \
                    patch.object(MODULE, 'matches_binary', return_value=matches), \
                    patch.object(MODULE.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 0, stdout=json.dumps(source))) as scan:
                self.sbom.import_distro_packages('syft')
                self.assertEqual(scan.called, matches)
        self.assertEqual({p['name'] for p in self.sbom.document['packages']}, {'KeePassXC', 'example'})
        self.sbom.finalize_document()

    def test_vcpkg_target_ownership_filters_unshipped_packages(self):
        self.deploy_binary('botan-3.dll', b'MZ\0\0')
        self.collect_deployed_files()
        installed = self.directory / 'vcpkg installed'
        info = installed / 'vcpkg/info'
        info.mkdir(parents=True)
        for triplet, port in [('x64-windows', 'botan'), ('x64-windows', 'unused'), ('x64-linux', 'botan')]:
            path = installed / triplet / 'share' / port / 'vcpkg.spdx.json'
            path.parent.mkdir(parents=True)
            source = document()
            source['packages'] = [package(port, 'SPDXRef-port'), package('abi', 'SPDXRef-binary')]
            path.write_text(json.dumps(source))
            (info / f'{port}_1.2.3_{triplet}.list').write_text(f'{triplet}/bin/{port}-3.dll\n')
        self.sbom.import_vcpkg_packages(str(installed), 'x64-windows')
        imported = self.sbom.document['packages'][1:]
        self.assertEqual([p['name'] for p in imported], ['botan'])
        self.assertEqual(imported[0]['versionInfo'], '1.2.3')
        self.sbom.finalize_document()

    def qt_fixture(self, tag_value=False):
        source = document()
        source['packages'] = [package('QtCore'), package('pcre2'), package('moc')]
        source['packages'][0]['licenseDeclared'] = 'LicenseRef-Qt'
        source['hasExtractedLicensingInfos'] = [{'licenseId': 'LicenseRef-Qt', 'extractedText': 'Example license'}]
        source['files'] = [{'SPDXID': 'SPDXRef-file', 'fileName': './lib/libQt6Core.so.6',
                            'checksums': [{'algorithm': 'SHA1', 'checksumValue': '0' * 40}]}]
        source['relationships'] = [
            {'spdxElementId': 'SPDXRef-QtCore', 'relationshipType': 'CONTAINS', 'relatedSpdxElement': 'SPDXRef-file'},
            {'spdxElementId': 'SPDXRef-QtCore', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-pcre2'}]
        prefix = self.directory / 'Qt'
        path = prefix / 'sbom' / ('qtbase.spdx' if tag_value else 'qtbase.spdx.json')
        path.parent.mkdir(parents=True)
        if tag_value:
            from spdx_tools.spdx.parser.json.json_parser import JsonLikeDictParser
            from spdx_tools.spdx.writer.tagvalue.tagvalue_writer import write_document_to_file
            write_document_to_file(JsonLikeDictParser().parse(source), str(path), validate=False)
        else:
            path.write_text(json.dumps(source))
        return prefix

    def check_qt(self, tag_value):
        self.deploy_binary('libQt6Core.so.6')
        self.collect_deployed_files()
        self.sbom.import_qt_packages(str(self.qt_fixture(tag_value)), '6.8.0')
        packages = self.sbom.document['packages'][1:]
        self.assertEqual({p['name'] for p in packages}, {'QtCore', 'pcre2'})
        qt = next(p for p in packages if p['name'] == 'QtCore')
        license_id = self.sbom.document['hasExtractedLicensingInfos'][0]['licenseId']
        self.assertEqual(qt['licenseDeclared'], license_id)
        self.assertNotEqual(license_id, 'LicenseRef-Qt')
        # Do not import supplier file hashes into the deployment inventory.
        self.assertEqual(len(self.sbom.document['files']), 1)
        self.assertNotEqual(self.sbom.document['files'][0]['checksums'][0]['checksumValue'], '0' * 40)
        self.sbom.finalize_document()

    def test_qt_json_and_transitive_components(self):
        self.check_qt(False)

    def test_static_link_inputs_and_vendored_components(self):
        installed = self.directory / 'installed'
        info = installed / 'vcpkg/info'
        info.mkdir(parents=True)
        for name in ('linked', 'unused'):
            path = installed / 'x64-linux/share' / name / 'vcpkg.spdx.json'
            path.parent.mkdir(parents=True)
            source = document()
            source['packages'] = [package(name, 'SPDXRef-port')]
            path.write_text(json.dumps(source))
            (info / f'{name}_1.2.3_x64-linux.list').write_text(f'x64-linux/debug/lib/lib{name}.a\n')
        inputs = self.directory / 'inputs.txt'
        inputs.write_text(f'LIBRARY|{installed}/x64-linux/debug/lib/liblinked.a\n'
                          'VENDORED|ykcore|src/thirdparty/ykcore/ykcore.c|1.20.0+keepassxc\n'
                          'VENDORED|zxcvbn|src/thirdparty/zxcvbn/zxcvbn.c\n')
        self.sbom.load_link_inputs(inputs)
        self.sbom.import_vcpkg_packages(str(installed), 'x64-linux')
        self.assertEqual({p['name'] for p in self.sbom.document['packages']},
                         {'KeePassXC', 'linked', 'ykcore', 'zxcvbn'})
        vendor = next(p for p in self.sbom.document['packages'] if p['name'] == 'ykcore')
        self.assertEqual(vendor['licenseDeclared'], 'BSD-2-Clause')
        self.assertEqual(vendor['versionInfo'], '1.20.0+keepassxc')
        self.assertEqual(len([r for r in self.sbom.document['relationships']
                              if r['relationshipType'] == 'DEPENDS_ON']), 3)
        self.sbom.finalize_document()

    def test_qt_tag_value(self):
        self.check_qt(True)

    def test_qt_cross_repository_dependencies(self):
        self.deploy_binary('libQt6Core.so.6')
        self.collect_deployed_files()
        prefix = self.qt_fixture()
        qtbase = prefix / 'sbom/qtbase.spdx.json'
        base = json.loads(qtbase.read_text())
        external = document()
        external['documentNamespace'] = 'https://example.org/qt-thirdparty'
        external['packages'] = [package('embedded-library')]
        base['externalDocumentRefs'] = [{'externalDocumentId': 'DocumentRef-thirdparty',
                                        'spdxDocument': external['documentNamespace'],
                                        'checksum': {'algorithm': 'SHA1', 'checksumValue': '0' * 40}}]
        base['relationships'].append({'spdxElementId': 'SPDXRef-QtCore', 'relationshipType': 'DEPENDS_ON',
                                      'relatedSpdxElement': 'DocumentRef-thirdparty:SPDXRef-embedded-library'})
        qtbase.write_text(json.dumps(base))
        (prefix / 'sbom/qt-thirdparty.spdx.json').write_text(json.dumps(external))
        self.sbom.import_qt_packages(str(prefix), '6.8.0')
        self.assertIn('embedded-library', {p['name'] for p in self.sbom.document['packages']})
        self.sbom.finalize_document()

    def test_qt_64_fallback_without_vcpkg(self):
        self.deploy_binary('libQt6Core.so.6')
        self.deploy_binary('plugins/platforms/libqxcb.so')
        self.collect_deployed_files()
        self.sbom.import_vcpkg_packages('', '')
        self.sbom.import_qt_packages(str(self.directory / 'Qt 6.4'), '6.4.2')
        qt = self.sbom.document['packages'][-1]
        self.assertEqual((qt['name'], qt['versionInfo']), ('Qt', '6.4.2'))
        self.assertNotIn('libqxcb.so', self.sbom.accounted)
        self.sbom.finalize_document()

    def test_colliding_supplier_ids_are_namespaced(self):
        source = document()
        source['packages'] = [package('library')]
        a = self.sbom.import_supplier_packages(source, {'SPDXRef-library'}, 'supplier-a')
        b = self.sbom.import_supplier_packages(source, {'SPDXRef-library'}, 'supplier-b')
        self.assertNotEqual(a, b)
        self.sbom.finalize_document()

    def test_missing_deployment_fails(self):
        result = subprocess.run([sys.executable, str(ROOT / 'utils/generate-sbom.py'),
                                 '--syft', 'unused', '--deploy-dir', str(self.directory / 'absent'),
                                 '--output', str(self.directory / 'output'), '--version', '2.8'],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_comments_are_only_in_debug_output(self):
        for debug in (False, True):
            with self.subTest(debug=debug):
                sbom = MODULE.DeploymentSbom(document(), self.deploy, '2.8.0')
                source = document()
                source['packages'] = [package('example')]
                source['packages'][0]['comment'] = 'Supplier comment'
                source['packages'][0]['licenseDeclared'] = 'LicenseRef-example'
                source['hasExtractedLicensingInfos'] = [{
                    'licenseId': 'LicenseRef-example', 'extractedText': 'License text', 'comment': 'License comment'}]
                sbom.import_supplier_packages(source, {'SPDXRef-example'}, 'test supplier')
                sbom.finalize_document(debug=debug)
                library = sbom.document['packages'][-1]
                self.assertEqual('sourceInfo' in library, debug)
                self.assertEqual('comment' in library, debug)
                self.assertEqual('comment' in sbom.document['creationInfo'], debug)
                license_info = sbom.document['hasExtractedLicensingInfos'][0]
                self.assertEqual('comment' in license_info, debug)
                self.assertEqual(license_info['extractedText'], 'License text')

    def test_failed_scan_removes_stale_output(self):
        output = self.directory / 'output.spdx.json'
        output.write_text('stale output')
        result = subprocess.run([sys.executable, str(ROOT / 'utils/generate-sbom.py'),
                                 '--syft', str(self.directory / 'missing-syft'), '--deploy-dir', str(self.deploy),
                                 '--output', str(output), '--version', '2.8'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_release_sidecars_append_to_full_artifact_names(self):
        output = self.directory / 'release'
        output.mkdir()
        for generator, artifact in [('ZIP', 'KeePassXC-2.8.0.zip'), ('WIX', 'KeePassXC-2.8.0.msi'),
                                    ('DragNDrop', 'KeePassXC-2.8.0.dmg'), (None, 'KeePassXC-2.8.0.AppImage')]:
            suffix = f'-{generator}' if generator else ''
            (self.directory / f'keepassxc{suffix}.spdx.json').write_text(artifact)
            RELEASE.Build._copy_sbom(self.directory, output, artifact, generator)
            self.assertEqual((output / f'{artifact}.spdx.json').read_text(), artifact)
        self.assertEqual(len(list(output.glob('*.spdx.json'))), 4)
        with self.assertRaises(RELEASE.Error):
            RELEASE.Build._copy_sbom(self.directory, output, 'missing', 'missing')

    def test_release_sbom_default_and_opt_out(self):
        import argparse
        parser = argparse.ArgumentParser()
        RELEASE.Build.setup_arg_parser(parser)
        for flags, enabled in [([], True), (['--no-sbom'], False)]:
            with self.subTest(flags=flags):
                args = vars(parser.parse_args([
                    '2.8.0', '--snapshot', '--use-system-deps', '--yes', *flags,
                    '--src-dir', str(ROOT), '--output-dir', str(self.directory / 'release')]))
                with patch.object(RELEASE.sys, 'platform', 'linux'), \
                        patch.object(RELEASE.Check, 'perform_basic_checks'), \
                        patch.object(RELEASE.Check, 'check_version_in_cmake'), \
                        patch.object(RELEASE.Build, 'build_linux') as build:
                    RELEASE.Build(parser).run(**args)
                self.assertIn('-DWITH_SBOM=' + ('ON' if enabled else 'OFF'),
                              build.call_args.kwargs['cmake_opts'])
                self.assertEqual(build.call_args.kwargs['no_sbom'], enabled)

    def test_appimage_scans_after_deployment_and_library_removal(self):
        import argparse
        app_dir = self.directory / 'AppDir'
        desktop = app_dir / 'usr/share/applications/org.keepassxc.KeePassXC.desktop'
        desktop.parent.mkdir(parents=True)
        desktop.write_text('[Desktop Entry]\n')
        is_binary_file = app_dir / 'usr/bin/keepassxc'
        is_binary_file.parent.mkdir(parents=True)
        is_binary_file.touch()
        libssl = app_dir / 'usr/lib/libssl.so.3'
        libssl.parent.mkdir(parents=True)
        libssl.touch()
        output = self.directory / 'release'
        output.mkdir()
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if command[0] == 'cmake':
                self.assertFalse(libssl.exists())
                self.assertIn('-DSBOM_DEPLOY_DIR=' + str(app_dir), command)
                (self.directory / 'keepassxc.spdx.json').write_text('sbom')

        with patch.object(RELEASE.Build, '_prepare_appimage_tool',
                          side_effect=lambda name, *args: self.directory / name), \
                patch.object(RELEASE, '_run', side_effect=run):
            RELEASE.Build(argparse.ArgumentParser())._build_linux_appimage(
                '2.8.0', ROOT, output, app_dir, self.directory, '/usr', 'x86_64', {}, sbom=True)
        self.assertEqual([Path(command[0]).name for command in commands],
                         ['linuxdeploy', 'linuxdeploy-plugin-qt', 'cmake', 'appimagetool'])
        self.assertTrue((output / 'KeePassXC-2.8.0-x86_64.AppImage.spdx.json').is_file())


if __name__ == '__main__':
    unittest.main()
