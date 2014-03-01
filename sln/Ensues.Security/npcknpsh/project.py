import os
import re
import shutil
import subprocess

import projectconfig

class Project:

    def __init__(self, project_dir, config = None):
        self.project_dir = project_dir
        self.config = config or projectconfig

    def process(self, command):
        err = subprocess.Popen(command).wait()
        return err

    def element_tree(self):
        import xml.etree.ElementTree
        return xml.etree.ElementTree

    def msbuild_path(self):
        return self.config.msbuild_path

    def nuget_path(self):
        return self.config.nuget_path

    def test_command(self):
        return self.config.test_command

    def project_name(self):
        return os.path.basename(os.path.normpath(self.project_dir))

    def project_file(self):
        return os.path.join(self.project_dir, self.project_name() + '.csproj')

    def project_file_namespace(self):
        return self.config.project_file_namespace

    def test_project(self):
        test_project_dir = os.path.join(self.project_dir, '..', self.project_name() + '.Tests')
        return Project(test_project_dir, self.config)

    def assembly_info_file(self):
        return os.path.join(self.project_dir, 'Properties', 'AssemblyInfo.cs')

    def assembly_file(self):
        return os.path.join(self.build_dir(), self.project_name() + '.dll')

    def build_configuration(self):
        return self.config.build_configuration
    
    def build_dir(self):
        return os.path.join(self.project_dir, 'bin', self.build_configuration())

    def nuget_dir(self):
        return os.path.join(self.project_dir, 'nuget')

    def nuspec_file(self):
        return os.path.join(self.nuget_dir(), self.project_name() + '.nuspec')

    def nuget_source(self):
        return self.config.nuget_source

    def nuget_api_key(self):
        return self.config.nuget_api_key

    def target_framework_versions(self):
        return self.config.target_framework_versions

    def framework_version_nuget_dir_map(self):
        return self.config.framework_version_nuget_dir_map

    def get_assembly_info_file_contents(self):
        with open(self.assembly_info_file(), 'r') as f:
            return f.read()

    def set_assembly_info_file_contents(self, contents):
        with open(self.assembly_info_file(), 'w') as f:
            f.write(contents)

    def get_version(self, version_type = 'AssemblyVersion'):

        contents = self.get_assembly_info_file_contents()

        lines = contents.split('\n')
        for line in lines:
            if 'assembly: ' + version_type in line:
                match = re.findall(r'\"(.+?)\"', line)[0]
                split = match.split('.')
                return split

        return []

    def increment_version(self, version_type = 'AssemblyFileVersion', version_index = 3, version_increment = 1):
        
        version = self.get_version(version_type)
        version[version_index] = str(int(version[version_index]) + version_increment)

        lines = self.get_assembly_info_file_contents().split('\n')
        for i, line in enumerate(lines):
            if 'assembly: ' + version_type in line:
                lines[i] = '[assembly: {}("{}")]'.format(version_type, '.'.join(version))

        self.set_assembly_info_file_contents('\n'.join(lines))

    def build(self, target_framework_version):

        project_xml_namespace = self.project_file_namespace()

        et = self.element_tree()
        et.register_namespace('', project_xml_namespace)

        project_file = self.project_file()
        project_xml_doc = et.parse(project_file)
        project_xml_root = project_xml_doc.getroot()

        for version_element in project_xml_root.iter('{' + project_xml_namespace + '}TargetFrameworkVersion'):
            version_element.text = target_framework_version

        project_xml_doc.write(project_file)

        cmd = '{} "{}" /p:configuration={}'.format(self.msbuild_path(), project_file, self.build_configuration())
        err = self.process(cmd)

        return err
        
    def test(self, target_framework_version):
        
        test_project = self.test_project()
        test_project.build(target_framework_version)

        test_cmd = self.test_command()
        test_assembly_file = test_project.assembly_file()

        cmd = '{} "{}"'.format(test_cmd, test_assembly_file)
        err = self.process(cmd)

        return err

    def pack(self):

        self.increment_version()

        versions = self.target_framework_versions()
        for version in versions:

            err = self.build(version)
            if err:
                return err

            err = self.test(version)
            if err:
                return err

            nuget_map = self.framework_version_nuget_dir_map()
            nuget_dir = nuget_map[version]
            nuget_dir = os.path.join(self.nuget_dir(), 'lib', nuget_dir)

            if os.path.exists(nuget_dir):
                shutil.rmtree(nuget_dir)

            build_dir = self.build_dir()
            shutil.copytree(build_dir, nuget_dir)
            
        nuget_dir = self.nuget_dir()
        nuget_path = self.nuget_path()
        nuspec_file = self.nuspec_file()

        version = self.get_version('AssemblyInformationalVersion')
        version = '.'.join(version)

        cmd = '{} pack "{}" -Version {} -OutputDirectory "{}"'.format(nuget_path, nuspec_file, version, nuget_dir)
        err = self.process(cmd)

        return err

    def push(self):

        err = self.pack()
        if err:
            return err

        version = self.get_version('AssemblyInformationalVersion')
        version = '.'.join(version)

        nuget_dir = self.nuget_dir()
        project_name = self.project_name()
        package_file_name = '{}.{}.nupkg'.format(project_name, version)
        package_file = os.path.join(nuget_dir, package_file_name)
        
        nuget_path = self.nuget_path()
        cmd = '{} push "{}"'.format(nuget_path, package_file)

        nuget_source = self.nuget_source()
        if nuget_source:
            cmd = '{} -Source {}'.format(cmd, nuget_source)

        nuget_api_key = self.nuget_api_key()
        if nuget_api_key:
            cmd = '{} -ApiKey {}'.format(cmd, nuget_api_key)

        err = self.process(cmd)
        return err
