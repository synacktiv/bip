#! python

import os
import sys
import shutil
import argparse
from distutils.dir_util import copy_tree


def install_generic(dest):
    """
        Method for installing Bip on Windows, this method do not install any
        plugins. This method will copy the bip folder and the plugin loader
        to their destination. Calling this method will delete previous version
        of Bip.

        :param str dest: The destination folder in which to install Bip.
        :return: True if the installation succeeded, False otherwise.
    """
    # Destination folders
    ida_plg = os.path.join(dest, "plugins") # ida folder for plugins
    ida_bipdst = os.path.join(ida_plg, "bip") # dest folder for bip
    ida_bipplg = os.path.join(ida_plg, "bipplugin") # folder for bip plugins
    ida_bipplginit = os.path.join(ida_bipplg, "__init__.py") # init file for bip plugins
    # Source folders
    current_dir = os.path.dirname(os.path.realpath(__file__))
    bip_dir = os.path.join(current_dir, "bip")
    bip_ldr = os.path.join(current_dir, "install", "idabip_loader.py")
    # check folders exist and create/delete them if necessary
    if not os.path.isdir(dest):
        print("{} path do not seems to exist, is IDA installed ?".format(dest))
        print("Aborting installation")
        return False
    if os.path.exists(ida_plg) and not os.path.isdir(ida_plg):
        print("{} path exist but is not a directory".format(ida_plg))
        print("Aborting installation")
        return False
    elif not os.path.exists(ida_plg):
        os.mkdir(ida_plg)
    if os.path.exists(ida_bipplg) and not os.path.isdir(ida_bipplg):
        print("{} path exist but is not a directory".format(ida_bipplg))
        print("Aborting installation")
        return False
    elif not os.path.exists(ida_bipplg):
        os.mkdir(ida_bipplg)
    if os.path.exists(ida_bipdst):
        shutil.rmtree(ida_bipdst)
    # copy the bip folder in plugin directory
    shutil.copytree(bip_dir, ida_bipdst)
    # copy bip plugin loader in ida directory
    shutil.copy(bip_ldr, ida_plg)
    # create __init__.py in bipplugin folder
    if not os.path.exists(ida_bipplginit):
        with open(ida_bipplginit, 'w'): pass
    return True



def install(dest=None):
    """
        This method will install bip at the destination folder. If a
        destination folder is not provided, this will take the default IDA
        folder: ``%APPDATA%\Hex-Rays\IDA Pro\`` for Windows and
        ``$HOME/.idapro`` for Linux and MacOSX.

        :param str dest: The destination folder in which to install Bip.
    """
    if dest is None:
        if sys.platform in ("linux", "linux2", "darwin"):
            dest = os.path.join(os.getenv('HOME'), '.idapro')
        elif sys.platform == "win32":
            dest = os.path.join(os.getenv('APPDATA'), 'Hex-Rays', 'IDA Pro')
        else:
            print("Unknwown OS do not know where to install")
            return
    print("Launching Bip install")
    if not install_generic(dest):
        print("Unable to install Bip")
    else:
        print("Bip has been succesfully installed")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dest', type=str, default=None,
            help='Destination folder where to install Bip')
    args = parser.parse_args()
    install(dest=args.dest)

if __name__ == "__main__":
    # execute only if run as a script
    main()



