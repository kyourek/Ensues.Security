import argparse
import os
import sys

import buildconfig

class Build:
    
    class ProjectNotFoundError(Exception):
        pass

    def __init__(self, config = None):
        self.config = config or buildconfig

    def project_class(self):
        return self.config.project_class

    def project_dir(self):
        
        project_dir = self.config.project_dir
        if project_dir:
            return project_dir

        script_file = os.path.abspath(sys.argv[0])
        script_path = os.path.dirname(script_file)
        
        current_path = script_path
        while True:

            items = os.listdir(current_path)
            items = [i for i in items if i.endswith('.csproj')]
            paths = [os.path.join(current_path, i) for i in items]
            files = [p for p in paths if os.path.isfile(p)]

            if len(files):
                file = files[0]
                return os.path.dirname(file)

            next_path = os.path.dirname(current_path)
            if next_path == current_path:
                raise Build.ProjectNotFoundError()

            current_path = next_path

    def process(self, pack_or_push):

        project_dir = self.project_dir()
        project_class = self.project_class()

        project = project_class(project_dir)

        err = 0

        if pack_or_push == 'pack':
            err = project.pack()
        if pack_or_push == 'push':
            err = project.push()

        return err

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description = 'Test, pack, and push NuGet packages for multiple framework target versions.'
    )
    parser.add_argument('pack_or_push', metavar = 'P', type = str, help = 'pack --or-- push')

    args = parser.parse_args()

    Build().process(args.pack_or_push)