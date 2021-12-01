import os
import platform
import sys
import multiprocessing
import subprocess
import glob

# find the ninja generator on windows.
def getGenerator(args):
    #osStr = (platform.system())
    #
    #if osStr == "Windows":
    #
    #    for x in args:
    #        if x.startswith("-G"):
    #            break
    #
    #    vswhereArgs = ['C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe', "-prerelease", "-latest", "-property", "installationPath"]
    #    rootpath = subprocess.check_output(vswhereArgs).decode("utf-8").strip()
    #
    #    ninja = rootpath + "/COMMON7/IDE/COMMONEXTENSIONS/MICROSOFT/CMAKE/Ninja/ninja.exe"
    #    cl = rootpath + "/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"
    #    cls = glob.glob(cl)
    #    if len(cls) > 0:
    #        cl = cls[-1];
    #
    #    # use ninja
    #    if os.path.exists(ninja) and os.path.exists(cl):
    #        return "-G \"Ninja\"  -DCMAKE_MAKE_PROGRAM=\"{0}\" -DCMAKE_C_COMPILER:FILEPATH=\"{1}\" -DCMAKE_CXX_COMPILER:FILEPATH=\"{1}\" ".format(ninja, cl)
    #    else:
    #        print("failed to find ninja at: {0}\n or cl".format(ninja))
    #
    # use the default
    return ""


def parseInstallArgs(args):
    prefix = ""
    doInstall = False
    for x in args:
        if x.startswith("--install="):
            prefix = x.split("=",1)[1]
            prefix = os.path.abspath(os.path.expanduser(prefix))
            idx = args.index(x)
            args[idx] = "-DCMAKE_INSTALL_PREFIX=" + prefix
            doInstall = True
        if x == "--install":
            idx = args.index(x)
            osStr = (platform.system())
            if osStr == "Windows":
                args[idx] = "-DCMAKE_INSTALL_PREFIX=c:/lib"
            else:
                args[idx] = "-DCMAKE_INSTALL_PREFIX=/usr/local"
            doInstall = True

    return (args, doInstall)

def getParallel(args):
    par = multiprocessing.cpu_count()
    for x in args:
        if x.startswith("--par="):
            val = x.split("=",1)[1]
            par = int(val)
            if par < 1:
                par = 1
            idx = args.index(x)
            args[idx] = ""
    return (args,par)


def replace(list, find, replace):
    if find in list:
        idx = list.index(find)
        list[idx] = replace;
    return list

def Build(projectName, argv):

    osStr = (platform.system())
    buildDir = ""
    config = ""
    buildType = ""
    
    # use sudo when installing?
    sudo = "--sudo" in argv;
    argv = replace(argv, "--sudo", "-DSUDO_FETCH=ON")
    if not sudo:
        argv.append("-DSUDO_FETCH=OFF")

    generator = getGenerator(argv)

    # do not automaticly download dependancies
    if "--noauto" in argv:
        argv = replace(argv, "--noauto", "")
        argv.append("-DFETCH_AUTO=OFF")
    else:
        argv.append("-DFETCH_AUTO=ON")

    # get install options
    argv, install = parseInstallArgs(argv)

    # get parallel build options
    argv, par = getParallel(argv)
    argv.append("-DPARALLEL_FETCH="+str(par))

    # do not run cmake config
    noConfig = "--nc" in argv
    argv = replace(argv, "--nc", "")

    # only run cmake config.
    setup = "--setup" in argv;
    argv = replace(argv, "--setup", "")

    # build type.
    if "--debug" in argv:
        buildType = "Debug"
    else:
        buildType = "Release"
    argv.append("-DCMAKE_BUILD_TYPE={0}".format(buildType))
    argv = replace(argv, "--debug", "")

    # build dir
    if osStr == "Windows":
        buildDir = "out/build/x64-{0}".format(buildType)
        config = "--config {0}".format(buildType)
    elif osStr == "Darwin":
        buildDir = "out/build/osx"
    else:
        buildDir = "out/build/linux"

    # convert args to a string.
    argStr = ""
    for a in argv:
        argStr = argStr + " " + a

    # parallel build
    parallel = ""
    if par != 1:
        parallel = " --parallel " + str(par)


    # build commands
    mkDirCmd = "mkdir -p {0}".format(buildDir); 
    CMakeCmd = "cmake  {0} -S . -B {1} {2} ".format(generator, buildDir, argStr)
    BuildCmd = "cmake --build {0} {1} {2} ".format(buildDir, config, parallel)
    InstallCmd = ""
    if sudo:
        sudo = "sudo "
    else:
        sudo = ""
    if install:
        InstallCmd = sudo
        InstallCmd += "cmake --install {0} {1} ".format(buildDir, config)

    # print and execute commands.    
    print("\n\n====== build.py ("+projectName+") ========")
    if not noConfig:
        print(mkDirCmd)
        print(CMakeCmd)

    if not setup:
        print(BuildCmd)
        if len(InstallCmd):
            print(InstallCmd)
    print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n")

    if not noConfig:
        os.system(mkDirCmd)
        os.system(CMakeCmd)

    if not setup:
        os.system(BuildCmd)

        if len(sudo) > 0:
            print("installing "+projectName+": {0}\n".format(InstallCmd))

        os.system(InstallCmd)



def help():

    print(" --install \n\tInstructs the script to install whatever is currently being built to the default location.")
    print(" --install=prefix  \n\tinstall to the provided predix.")
    print(" --sudo  \n\twhen installing, use sudo. May require password.")
    print(" --par=n  \n\twhen building do use parallel  builds with n threads. default = num cores.")
    print(" --noauto  \n\twhen building do not automaticly fetch dependancies.")
    print(" --par=n  \n\twhen building do use parallel  builds with n threads. default = num cores.")
    print(" --debug  \n\tdebug build.")
    print("any additioanl arguments are forwared to cmake.\n")

    print("-build the library")
    print("     python build.py")
    print("-build the library with cmake configurations")
    print("     python build.py --debug -DLIBPSI_ENABLE_X=ON")
    print("-build the library and install with sudo")
    print("     python build.py --install --sudo")
    print("-build the library and install to prefix")
    print("     python build.py --install=~/my/install/dir ")



def main(projectName, argv):

    if "--help" in argv:
        help()
        return 

    # build the project.
    Build(projectName, argv)

if __name__ == "__main__":

    main("LIBPSI", sys.argv[1:])
