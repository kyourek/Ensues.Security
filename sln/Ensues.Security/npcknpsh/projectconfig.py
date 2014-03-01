import os

msbuild_path = r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'

test_command = r'"C:\Program Files (x86)\NUnit 2.6.3\bin\nunit-console.exe"'

project_file_namespace = 'http://schemas.microsoft.com/developer/msbuild/2003'

build_configuration = 'Release'

nuget_path = os.path.expanduser(r'~\Programs\NuGet\nuget.exe')

nuget_source = None

nuget_api_key = None

target_framework_versions = [
    'v4.0',
    'v4.5',
    'v4.5.1'
]

framework_version_nuget_dir_map = {
    'v3.5': 'net35',
    'v4.0': 'net40',
    'v4.5': 'net45',
    'v4.5.1': 'net451'
}