#!/usr/bin/env python3
import os
import os.path
import re
import subprocess
import sys
import zipfile

object_file_search_paths = [
    '/Applications',
    '/Library',
    '/System',
    '/usr',
    os.environ['HOME'],
]


if not os.path.isfile('mach-o-files.txt'):
    print('Searching for Mach-O files...')

    import magic

    args = [
        '/usr/bin/find',
        *object_file_search_paths,
            '(',
                    '-perm', '+0111',
                '-or',
                    '-name', '*.dylib',
            ')',
        '-and',
            '-type', 'f',
    ]
    executable_files = subprocess.run(args, capture_output=True, text=True).stdout

    count = 0

    with open('mach-o-files.txt', 'w') as mach_o_files:
        for line in executable_files.split('\n'):
            line = line.rstrip()
            if line == '/usr/bin/sudo':
                continue
            if line.startswith('/usr/libexec'):
                continue
            if line.startswith('/usr/sbin'):
                continue
            if line == '':
                continue

            m = magic.from_file(line)

            if 'Mach-O' in m:
                print(line, file=mach_o_files)
                count += 1

    print('Found', count)


class ObjectFile:
    def __init__(self, object_path):
        self.path = object_path
        self.filetype = None
        self.dylibs = []
        self.plugins = []


object_files = {}
objdump_parsers = {}


for line in open('mach-o-files.txt'):
    object_path = line.rstrip()
    object_files[object_path] = ObjectFile(object_path)


if not os.path.isfile('objdumps.zip'):
    print('Extracting Mach-O file headers...')

    objdump_exe = subprocess.run(['/usr/bin/xcrun', '-f', 'objdump'],
                                 check=True,
                                 capture_output=True,
                                 text=True).stdout.rstrip()

    def objdump(object_path):
        args = [objdump_exe, '-arch=x86_64', '-macho', '-private-headers', '-non-verbose', object_path]
        try:
            completed_proc = subprocess.run(args, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            print('WARNING')
            print('object_path', object_path)
            print('objdump died')
            print()
            return None

        stdout = completed_proc.stdout
        stderr = completed_proc.stderr

        if 'does not contain architecture' in stderr:
            return None
        if 'No architecture specified' in stderr:
            return None

        return stdout

    count = 0

    with zipfile.ZipFile('objdumps.zip', 'w') as z:
        for object_file in object_files.values():
            objdump_output = objdump(object_file.path)
            if not objdump_output:
                continue
            z.writestr(object_file.path, objdump_output)
            count += 1

    print('Extracted', count)


class ObjDumpParser:
    filetypes = {
        2: 'Executable',
        6: 'DyLib',
        7: 'Dynamic linker',
        8: 'Bundle',
        9: 'DyLib stub',
        11: 'Kernel extension'
    }

    loader_commands = set([
        'LC_BUILD_VERSION',
        'LC_CODE_SIGNATURE',
        'LC_DATA_IN_CODE',
        'LC_DYLD_ENVIRONMENT',
        'LC_DYLD_INFO',
        'LC_DYLD_INFO_ONLY',
        'LC_DYLIB_CODE_SIGN_DRS',
        'LC_DYSYMTAB',
        'LC_FUNCTION_STARTS',
        'LC_ID_DYLIB',
        'LC_ID_DYLINKER',
        'LC_LAZY_LOAD_DYLIB',
        'LC_LOAD_DYLIB',
        'LC_LOAD_DYLINKER',
        'LC_LOAD_UPWARD_DYLIB',
        'LC_LOAD_WEAK_DYLIB',
        'LC_MAIN',
        'LC_REEXPORT_DYLIB',
        'LC_ROUTINES_64',
        'LC_RPATH',
        'LC_SEGMENT_64',
        'LC_SEGMENT_SPLIT_INFO',
        'LC_SOURCE_VERSION',
        'LC_SUB_CLIENT',
        'LC_SUB_FRAMEWORK',
        'LC_SYMTAB',
        'LC_UNIXTHREAD',
        'LC_UUID',
        'LC_VERSION_MIN_IPHONEOS',
        'LC_VERSION_MIN_MACOSX',
        'LC_VERSION_MIN_TVOS',
        'LC_VERSION_MIN_WATCHOS',
    ])

    environ_keys = set([
        'DYLD_VERSIONED_FRAMEWORK_PATH',
    ])

    subpaths_with_missing_dylib = [
        '/Library/Caches/com.apple.xbs/Sources/iTunesOpenJDK/iTunesOpenJDK-180.2/freetype/lib/libfreetype.6.dylib',
        'X11',
    ]

    object_subpaths_with_missing_dylibs = [
        'appletvos',
        'Application Loader.app',
        'iphoneos',
        'Simulator.app',
        'Simulator.platform',
        'simulator/',
        'TLA+ Toolbox.app',
        'TsunagariC-Testing',
        'watchos',
        'Xcode.app/Contents/Developer/usr/share/xcs/CouchDB',
    ]

    strange_exe_files = {
        'TLA+ Toolbox': 'toolbox',
    }

    def __init__(self, object_file):
        self.object_file = object_file
        self.objdump_output = None
        self.lines = objdump_output.split('\n')
        self.environ = {}
        self.install_name = None
        self.loader_path = None
        self.executable_path = None
        self.executable_file = None
        self.rpaths = []
        self.expanded_rpaths = []
        self.load_dylib_commands = []
        self.load_weak_dylib_commands = []

        assert(self.lines[1] == 'Mach header')

    def parse(self, objdump_output):
        self.objdump_output = objdump_output

        self._parse_filetype()
        self._set_loader_and_executable_paths()
        self._parse_load_commands()

        self.objdump_output = None

    def resolve_dylibs(self):
        self._evaluate_load_dylib_commands()

    def _parse_filetype(self):
        m = re.search(r'^ *[^ ]* *\d* *\d* *[^ ]* *(\d*)', self.lines[3])
        assert(m)

        filetype_code = int(m[1])

        try:
            object_file.filetype = self.filetypes[filetype_code]
        except:
            pass

        if not object_file.filetype:
            print('object_file.path', self.object_file.path)
            print('filetype', filetype_code)
            raise Exception('Unknown file type')

    def _set_loader_and_executable_paths(self):
        slash = self.object_file.path.rindex('/')
        loader_path = self.object_file.path[0:slash]

        self.loader_path = loader_path

        filetype = self.object_file.filetype

        if filetype == 'Executable':
            executable_path = loader_path
        elif filetype == 'DyLib':
            self._set_dylib_executable_path()
            return
        elif filetype == 'Dynamic linker':
            return
        elif filetype == 'Bundle':
            executable_path = None
        elif filetype == 'DyLib stub':
            return
        elif filetype == 'Kernel extension':
            executable_path = None

        self.executable_path = executable_path

    def _set_dylib_executable_path(self):
        path = self.object_file.path

        app_ext_start = path.rfind('.appex/')
        if app_ext_start == -1:
            app_ext_start = path.rfind('.app/')
        if app_ext_start == -1:
            return
        app_ext_end = path.find('/', app_ext_start)

        self.executable_path = path[0:app_ext_end] + '/Contents/MacOS'

        app_name_start = path.rindex('/', 0, app_ext_start)
        app_name = path[app_name_start+1:app_ext_start]

        if app_name in self.strange_exe_files:
            app_name = self.strange_exe_files[app_name]

        self.executable_file = self.executable_path + '/' + app_name

    def _parse_load_commands(self):
        cmd = None

        for line in self.lines[4:]:
            m = re.search(r'^ *([^ ]*) *(.*)', line)
            assert(m)

            key = m[1]
            value = m[2]

            if key == 'cmd':
                cmd = value
                if not cmd in self.loader_commands:
                    print('object_file.path', self.object_file.path)
                    print(self.objdump_output)
                    print('cmd', cmd)
                    raise Exception('Unknown loader command')
            elif cmd == 'LC_DYLD_ENVIRONMENT' and key == 'name':
                for assignment in value.split(':'):
                    key, value = assignment.split('=')
                    if not key in self.environ_keys:
                        print('object_file.path', self.object_file.path)
                        print(assignment)
                        raise Exception('Unknown environment variable')
                    self.environ[key] = value
            elif cmd == 'LC_ID_DYLIB' and key == 'name':
                m = re.search(r'^(.*) \(offset 24\)$', value)
                assert(m)

                name = m[1]
                self.install_name = name
            elif cmd == 'LC_LAZY_LOAD_DYLIB' and key == 'name':
                self._add_dylib(value, weak=False)
            elif cmd == 'LC_LOAD_DYLIB' and key == 'name':
                self._add_dylib(value, weak=False)
            elif cmd == 'LC_LOAD_WEAK_DYLIB' and key == 'name':
                self._add_dylib(value, weak=True)
            elif cmd == 'LC_LOAD_UPWARD_DYLIB' and key == 'name':
                self._add_dylib(value, weak=False)
            elif cmd == 'LC_RPATH' and key == 'path':
                self._add_rpath(value)

    def _add_dylib(self, name, weak):
        m = re.search(r'^(.*) \(offset 24\)$', name)
        assert(m)
        name = m[1]

        if weak:
            self.load_weak_dylib_commands.append(name)
        else:
            self.load_dylib_commands.append(name)

    def _add_rpath(self, path):
        m = re.search(r'^(.*) \(offset 12\)$', path)
        assert(m)
        path = m[1]

        expanded_path = None

        if path.startswith('@loader_path'):
            expanded_path = self.loader_path + path[12:]
        elif path.startswith('@executable_path'):
            if self.executable_path:
                expanded_path = self.executable_path + path[16:]
        else:
            expanded_path = path

        if expanded_path:
            expanded_path = os.path.realpath(expanded_path)

        self.rpaths.append(path)
        self.expanded_rpaths.append(expanded_path)

    def _evaluate_load_dylib_commands(self):
        for dylib_name in self.load_dylib_commands:
            self._evaluate_load_dylib_command(dylib_name, weak=False)
        for dylib_name in self.load_weak_dylib_commands:
            self._evaluate_load_dylib_command(dylib_name, weak=True)

    def _evaluate_load_dylib_command(self, dylib_name, weak):
        if dylib_name.startswith('@loader_path'):
            dylib_name = self.loader_path + dylib_name[12:]
        elif dylib_name.startswith('@executable_path'):
            dylib_name = self._search_executable_path(dylib_name[16:])
        elif dylib_name.startswith('@rpath'):
            dylib_name = self._search_rpaths(dylib_name[6:])

        if not dylib_name:
            return

        dylib_name = os.path.realpath(dylib_name)

        if not os.path.exists(dylib_name):
            if self._is_known_missing_dylib(dylib_name):
                return
            if weak:
                return
            print('object_file.path', self.object_file.path)
            print('dylib_name', dylib_name)
            raise Exception('dylib not found')
        if not dylib_name in object_files:
            print('object_file.path', self.object_file.path)
            print('dylib_name', dylib_name)
            raise Exception('dylib not in object_files')

        # TODO: Check install name.

        self.object_file.dylibs.append(dylib_name)

    def _is_known_missing_dylib(self, dylib_name):
        for subpath in self.subpaths_with_missing_dylib:
            if subpath in dylib_name:
                return True
        for subpath in self.object_subpaths_with_missing_dylibs:
            if subpath in self.object_file.path:
                return True
        return False

    def _search_executable_path(self, dylib_name):
        if self.executable_path:
            return self.executable_path + dylib_name

        print('WARNING: dylib not found')
        print('object_file.path', self.object_file.path)
        print('dylib_name', dylib_name)

        return None

    def _search_rpaths(self, dylib_name):
        for expanded_rpath in self.expanded_rpaths:
            if not expanded_rpath:
                continue
            candidate = expanded_rpath + dylib_name
            if os.path.exists(candidate):
                return candidate

        if self.object_file.filetype == 'DyLib' and self.executable_file in objdump_parsers:
            exe_parser = objdump_parsers[self.executable_file]

            for expanded_rpath in exe_parser.expanded_rpaths:
                if not expanded_rpath:
                    continue
                candidate = expanded_rpath + dylib_name
                if os.path.exists(candidate):
                    return candidate

        candidate = self.loader_path + dylib_name
        if os.path.exists(candidate):
            return candidate

        print('WARNING: dylib not found')
        print('object_file.path', self.object_file.path)
        print('loader_path', self.loader_path)
        print('executable_path', self.executable_path)
        for i in range(len(self.rpaths)):
            rpath = self.rpaths[i]
            expanded_rpath = self.expanded_rpaths[i]
            if not expanded_rpath:
                print('rpath', rpath, '-> ???')
            elif rpath != expanded_rpath:
                print('rpath', rpath, '->', expanded_rpath)
            else:
                print('rpath', rpath)
        print('dylib_name', '@rpath' + dylib_name)
        print()

        return None


if not os.path.isfile('loads.zip'):
    print('Computing loader dependencies...')

    with zipfile.ZipFile('objdumps.zip') as z:
        for object_file in object_files.values():
            path = object_file.path

            try:
                objdump_output = str(z.read(path), encoding='utf-8')
            except:
                continue

            objdump_parsers[path] = ObjDumpParser(object_file)
            objdump_parsers[path].parse(objdump_output)

        for object_file in object_files.values():
            path = object_file.path

            if not path in objdump_parsers:
                continue

            objdump_parsers[path].resolve_dylibs()

    count = 0

    with zipfile.ZipFile('loads.zip', 'w') as z:
        for object_file in object_files.values():
            path = object_file.path

            if not path in objdump_parsers:
                continue

            z.writestr(path, '\n'.join(object_file.dylibs))
            count += len(object_file.dylibs)

    print('Found', count, 'dependencies')

z = zipfile.ZipFile('loads.zip')

def read_dylibs(path):
    try:
        dylibs = str(z.read(path), encoding='utf-8')
    except:
        return []

    if dylibs == '':
        return []
    else:
        return dylibs.split('\n')


def search(path, seen=set(), indent=0):
    for _ in range(indent):
        print('\t', end='')
    print(path)
    children_to_print = []
    for child in sorted(read_dylibs(path)):
        if child not in seen:
            seen.add(child)
            children_to_print.append(child)
    for child in children_to_print:
        search(child, seen, indent + 1)


for path in sys.argv[1:]:
    search(path)
