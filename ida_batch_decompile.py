#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : <github.com/tintinweb>
"""
IdaBatchDecompile Plugin and Script adds annotation and batch decompilation functionality to IDA Pro

* requires hexrays decompiler plugin

Usage:

* as idascript in ida gui mode: IDA Pro -> File/Script file... -> IdaDecompileBatch ...
* as idascript in ida cmdline mode: ida(w|w64) -B -M -S"<path_to_this_script> \"--option1\" \"--option2\"", "<target>"
 * see --help for options
* as Plugin: follow ida documentation on how to add python plugins

"""
import sys
import json
import glob
import subprocess
import shutil
import os
import tempfile
from optparse import OptionParser

import idaapi
import idautils
from idc import *

if idaapi.IDA_SDK_VERSION >= 700:
    import ida_idaapi
    import ida_kernwin
    from idaapi import *
    from idc import *

import logging

logger = logging.getLogger(__name__)


class IdaLocation(object):
    """ Wrap idautils Function
    """

    def __init__(self, location):
        self.at = location
        # self.name = GetFunctionName(location)
        self.name = GetFuncOffset(location)
        self.start = 0
        self.end = 0
        self.func_offset = 0
        try:
            _func = idaapi.get_func(location)
            self.start = _func.startEA
            self.end = _func.endEA  # ==FindFuncEnd(location)
            self.func_offset = self.start - self.at
        except Exception, e:
            logger.exception(e)
        if not self.name:
            self.indirect = True
        else:
            self.indirect = False

    def __repr__(self, *args, **kwargs):
        return "<Function %r at 0x%x (0x%x::0x%x)>" % (self.name, self.at,
                                                       self.start, self.end)

    def get_xrefs(self):
        return (IdaLocation(x.frm) for x in idautils.XrefsTo(self.at))

    def get_coderefs(self):
        return (IdaLocation(frm) for frm in idautils.CodeRefsTo(self.at, 0))

    def as_dict(self):
        return {'at': self.at, 'name': self.name}

    def decompile(self):
        """ decompile function
        """
        try:
            return idaapi.decompile(self.at)
        except idaapi.DecompilationFailure, e:
            return repr(str(e))
        text = str(idaapi.decompile(self.at)).strip()
        '''
        sprintf:
        Python>for w in idaapi.decompile(0x00001578 ).lvars: print w.name
            s
            format
            result
        '''
        # decompile.arguments
        # for w in idaapi.decompile(0x00001EF0 ).lvars: print w.name
        if not grep:
            return text.split('\n')
        # return all lines 
        return [line.strip() for line in text.split('\n') if grep in line]

    def get_function_args(self):
        # find the stack frame
        stack = GetFrame(self.start)
        stack_size = GetStrucSize(stack)
        # figure out all of the variable names
        # base is either ' s' ... saved register or ' r' ... return address
        base = GetMemberOffset(stack, ' s')
        if base == -1:
            base = GetMemberOffset(stack, ' r')
        if base == -1:
            # no ' s' no ' r' assume zero
            base == 0
        stack_vars = []

        for memberoffset in xrange(stack_size):
            previous = stack_vars[-1] if len(stack_vars) else None
            var_name = GetMemberName(stack, memberoffset)
            if not var_name or (previous and var_name == previous.get("name")):
                # skip that entry, already processed
                continue

            offset = GetMemberOffset(stack, var_name) - base
            size = GetMemberSize(stack, memberoffset)
            if previous:
                diff = offset - previous['offset']
                previous['diff_size'] = diff
            stack_vars.append({'name': var_name,
                               'offset': offset,
                               'offset_text': '[bp%Xh]' % offset if offset < 0 else '[bp+%Xh]' % offset,
                               'size': size,
                               'diff_size': size})
        return stack_size, stack_vars


class IdaHelper(object):
    """ Namespace for ida helper functions
    """

    @staticmethod
    def get_functions():
        return (IdaLocation(f) for f in idautils.Functions())

    @staticmethod
    def get_imports():
        for i in xrange(0, idaapi.get_import_module_qty()):
            name = idaapi.get_import_module_name(i)
            if name:
                yield name

    @staticmethod
    def decompile_full(outfile):
        return idaapi.decompile_many(outfile, None, 0)

    @staticmethod
    def annotate_xrefs():
        stats = {'annotated_functions': 0, 'errors': 0}
        for f in IdaHelper.get_functions():
            try:
                function_comment = GetFunctionCmt(f.start, 0)
                if '**** XREFS ****' in function_comment:
                    logger.debug("[i] skipping function %r, already annotated." % f.name)
                    continue
                xrefs = [x.name for x in f.get_coderefs()]
                comment = []
                if function_comment:
                    comment.append(function_comment)
                comment.append("***** XREFS *****")
                comment.append("* # %d" % len(xrefs))
                comment.append(', '.join(xrefs))
                comment.append("*******************")
                SetFunctionCmt(f.start, '\n'.join(comment), 0)
                stats['annotated_functions'] += 1
            except Exception as e:
                print ("Annotate XRefs: %r"%e)
                stats['errors'] += 1
        print "[+] stats: %r" % stats
        print "[+] Done!"

    @staticmethod
    def annotate_functions_with_local_var_size():
        stats = {'annotated_functions': 0, 'errors': 0}
        for f in IdaHelper.get_functions():
            try:
                function_comment = GetFunctionCmt(f.start, 0)
                if '**** Variables ****' in function_comment:
                    logger.debug("[i] skipping function %r, already annotated." % f.name)
                    continue
                size, stack_vars = f.get_function_args()
                comment = []
                if function_comment:
                    comment.append(function_comment)
                comment.append("**** Variables ****")
                comment.append("* stack size: %s" % size)
                for s in stack_vars:
                    comment.append(json.dumps(s))
                comment.append("*******************")
                SetFunctionCmt(f.start, '\n'.join(comment), 0)
                stats['annotated_functions'] += 1
            except Exception, e:
                print ("Annotate Funcs: %r" % e)
                stats['errors'] += 1
        print "[+] stats: %r" % stats
        print "[+] Done!"


class IdaDecompileBatchController(object):
    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
        self.is_ida64 = GetIdbPath().endswith(".i64")  # hackhackhack - check if we're ida64 or ida32
        logger.debug("[+] is_windows: %r" % self.is_windows)
        logger.debug("[+] is_ida64: %r" % self.is_ida64)
        self.my_path = os.path.abspath(__file__)
        self.temp_path = None
        self._init_target()
        # settings (form)
        # todo: load from configfile if available.
        self.output_path = None
        self.chk_annotate_stackvar_size = False
        self.chk_annotate_xrefs = False
        self.chk_decompile_imports = False
        self.chk_decompile_imports_recursive = False
        self.chk_decompile_alternative = False
        # self.ida_home = idaapi.idadir(".")
        self.ida_home = GetIdaDirectory()
        # wait for ida analysis to finish
        self.wait_for_analysis_to_finish()
        if not idaapi.init_hexrays_plugin():
            logger.warning("forcing hexrays to load...")
            self.load_plugin_decompiler()
        if not idaapi.init_hexrays_plugin():
            raise Exception("hexrays decompiler is not available :(")

    def _init_target(self):
        self.target_path = idc.GetInputFilePath()
        self.target_file = idc.GetInputFile()
        self.target_dir = os.path.split(self.target_path)[0]
        logger.debug("reinitializing target: %r" % self.target_file)

    def init_tempdir(self):
        self.temp_path = self.temp_path or tempfile.mkdtemp(prefix="idbc_")
        logger.debug("[i] using tempdir: %r" % self.temp_path)

    def remove_tempdir(self):
        if not self.temp_path:
            return
        logger.debug("[i] removing tempdir: %r" % self.temp_path)
        shutil.rmtree(self.temp_path)
        self.temp_path = None

    def wait_for_analysis_to_finish(self):
        logger.debug("[+] waiting for analysis to finish...")
        idaapi.autoWait()
        idc.Wait()
        logger.debug("[+] analysis finished.")

    def load_plugin_decompiler(self):
        # load decompiler plugins (32 and 64 bits, just let it fail)
        logger.debug("[+] trying to load decompiler plugins")
        if self.is_ida64:
            # 64bit plugins
            idc.RunPlugin("hexx64", 0)
        else:
            # 32bit plugins
            idc.RunPlugin("hexrays", 0)
            idc.RunPlugin("hexarm", 0)
        logger.debug("[+] decompiler plugins loaded.")

    def run(self):
        files_decompiled = []
        self._init_target()

        if self.chk_decompile_imports:
            self.init_tempdir()
            if self.chk_decompile_imports_recursive:
                pass
            for image_type, image_name, image_path in self.enumerate_import_images():
                try:
                    self.exec_ida_batch_decompile(target = image_path, output = self.output_path,
                                                  annotate_stackvar_size = self.chk_annotate_stackvar_size,
                                                  annotate_xrefs = self.chk_annotate_xrefs,
                                                  imports = self.chk_decompile_imports,
                                                  recursive = self.chk_decompile_imports_recursive,
                                                  experimental_decomile_cgraph = self.chk_decompile_alternative)
                    files_decompiled.append(image_path)
                except subprocess.CalledProcessError, cpe:
                    logger.warning("[!] failed to decompile %r - %r" % (image_path, cpe))

            self.remove_tempdir()

        if self.chk_annotate_stackvar_size:
            self.annotate_stack_variable_size()
        if self.chk_annotate_xrefs:
            self.annotate_xrefs()

        if self.chk_decompile_alternative:
            raise NotImplemented("Not yet implemented")
            pass
        else:
            self.decompile_all(self.output_path)
            files_decompiled.append(self.target_file)

        logger.info("[+] finished decompiling: %r" % files_decompiled)
        logger.info("    output dir: %s"%self.output_path if self.output_path else self.target_dir)
        return files_decompiled

    def annotate_stack_variable_size(self):
        logger.debug("[+] annotating function stack variables")
        IdaHelper.annotate_functions_with_local_var_size()
        logger.debug("[+] done.")

    def annotate_xrefs(self):
        logger.debug("[+] annotating function xrefs")
        IdaHelper.annotate_xrefs()
        logger.debug("[+] done.")

    def file_is_decompilable(self, path):
        with open(path, 'rb') as ftest:
            magic = ftest.read(4)
            if magic == 'MZ\x90\x00':
                return 'pe/dos'
            elif magic == "\x7fELF":
                return 'elf'
        return None

    def enumerate_import_images(self):
        for import_name in IdaHelper.get_imports():
            logger.debug("[i] trying to find image for %r" % import_name)
            for image_path in glob.glob(os.path.join(self.target_dir, import_name) + '*'):
                image_type = self.file_is_decompilable(image_path)
                if image_type:
                    logger.debug("[i] got image %r as %r" % (image_path, image_type))
                    yield image_type, os.path.split(image_path)[1], image_path
                    # I do not think there's any need to check other files with the same name ?!
                    break

    def enumerate_files(self, recursive=False):
        for root, dirs, files in os.walk(self.target_dir):
            for name in files:
                fpath = os.path.join(root, name)
                logger.debug("[+] checking %r" % fpath)
                try:
                    ftype = self.file_is_decompilable(fpath)
                    if ftype:
                        logger.debug("[+] is candidate %r" % [fpath, ftype])
                        yield ftype, name, fpath
                except IOError: pass

    def decompile_all(self, outfile=None):
        outfile = self._get_suggested_output_filename(outfile or self.target_path)
        logger.warning(outfile)
        logger.debug("[+] trying to decompile %r as %r" % (self.target_file,
                                                           os.path.split(outfile)[1]))
        IdaHelper.decompile_full(outfile)
        logger.debug("[+] finished decompiling %r as %r" % (self.target_file,
                                                            os.path.split(outfile)[1]))

    def _get_suggested_output_filename(self, target):
        # /a/b/c/d/e/bin.ext
        # target is a directory
        if os.path.isdir(target):
            fname, fext = os.path.splitext(self.target_file)
            return '%s.c' % os.path.join(target, fname)
        # target is not a directory
        root, fname = os.path.split(target)
        if fname:
            fname, fext = os.path.splitext(fname)  # bin,ext
        else:
            fname, fext = os.path.splitext(self.target_file)

        # obsolete
        # suggested_outpath = '%s.c'%os.path.join(root,fname)
        # if not os.path.exists(suggested_outpath):
        #    return suggested_outpath
        return '%s.c' % os.path.join(root, fname)

    def exec_ida_batch_decompile(self, target, output, annotate_stackvar_size, annotate_xrefs, imports, recursive,
                                 experimental_decomile_cgraph):
        logger.debug("[+] batch decompile %r" % target)
        # todo: pass commandlines,
        # todo parse commandline
        script_args = ['--output=%s' % output]
        if annotate_stackvar_size:
            script_args.append("--annotate-stackvar-size")
        if annotate_xrefs:
            script_args.append("--annotate-xrefs")
        if imports:
            script_args.append("--imports")
        if recursive:
            script_args.append("--recursive")
        if experimental_decomile_cgraph:
            script_args.append("--experimental-decompile-cgraph")

        script_args = ['\\"%s\\"' % a for a in script_args]
        command = "%s %s" % (self.my_path, ' '.join(script_args))
        self._exec_ida_batch(target, command)

    def _exec_ida_batch(self, target, command):
        # build exe path
        if self.is_windows:
            ida_exe = os.path.join(self.ida_home, 'idaw64.exe' if self.is_ida64 else 'idaw.exe')
        else:
            ida_exe = os.path.join(self.ida_home, 'idal64' if self.is_ida64 else 'idal')
        '''
        https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
        -B  ..  Batch mode
        -M  ..  disable mouse
        -c  ..  create new database
        -o  ..  database output path
        -S  ..  execute script
        '''
        #temp_path = os.path.join(self.temp_path, os.path.splitext(os.path.split(target)[1])[0] + '.idb')
        cmd = [ida_exe, '-B', '-M', '-c', '-o"%s"'%self.temp_path if self.temp_path else '', '-S"%s"' % command, '"' + target + '"']
        logger.debug(' '.join(cmd))
        logger.debug('[+] executing: %r' % cmd)
        #return 0
        # TODO: INSECURE!
        return subprocess.check_call(' '.join(cmd), shell=True)


class TestEmbeddedChooserClass(Choose,Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, nb = 5, flags=0):
        Choose.__init__(self,
                         title,
                         [["Type", 10], ["Name", 10], ["Path", 30]],
                         flags=flags)
        Choose2.__init__(self,
                         title,
                         [ ["Type", 10], ["Name", 10],  ["Path", 30] ],
                         embedded=True, width=50, height=10, flags=flags)
        self.n = 0
        self.items = []
        self.icon = 5
        self.selcount = 0

        self.selected = []

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnRefresh(self, n):
        print "refresh %s"%n

    def OnSelectionChange(self, sel_list):
        self.selected = sel_list

    def getSelected(self):
        for idx in self.selected:
            yield self.items[idx-1]

    def addItem(self, e):
        if e not in self.items:
            self.items.append(e)


class DecompileBatchForm(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """

    def __init__(self, idbctrl, enumerate_imports=True, enumerate_other=False):
        self.idbctrl = idbctrl
        self.EChooser = TestEmbeddedChooserClass("Batch Decompile", flags=Choose2.CH_MULTI)
        self.propagateItems(enumerate_imports=enumerate_imports, enumerate_other=enumerate_other)
        Form.__init__(self,
                      r"""Ida Batch Decompile ...
{FormChangeCb}
<##Target    :{target}>
<##OutputPath:{outputPath}>
<##Annotate StackVar Size:{chkAnnotateStackVars}>
<##Annotate Func XRefs   :{chkAnnotateXrefs}>
<##Process Imports       :{chkDecompileImports}>
<##Cgraph (experimental) :{chkDecompileAlternative}>{cGroup1}>


<##Scan Target Directory:{btnLoad}> <##Recursive:{chkDecompileImportsRecursive}>{cGroup2}>
<##Decompile!:{btnProcessFiles}>
<Please select items to decompile:{cEChooser}>


""", {
                          'target': Form.FileInput(swidth=50, open=True, value=idbctrl.target_path),
                          'outputPath': Form.DirInput(swidth=50, value=idbctrl.output_path),
                          'cGroup1': Form.ChkGroupControl(("chkAnnotateStackVars", "chkAnnotateXrefs",
                                                           "chkDecompileImports",
                                                           "chkDecompileAlternative")),
                          'cGroup2': Form.ChkGroupControl(("chkDecompileImportsRecursive", )),
                          'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                          'btnLoad':  Form.ButtonInput(self.OnButtonLoad),
                          'btnProcessFiles': Form.ButtonInput(self.OnButtonProcess),
                          'cEChooser': Form.EmbeddedChooserControl(self.EChooser),
                      })
        self.Compile()

    def propagateItems(self, enumerate_imports=False, enumerate_other=False):
        self.EChooser.addItem([self.idbctrl.file_is_decompilable(self.idbctrl.target_path),
                               os.path.split(self.idbctrl.target_path)[1],
                               self.idbctrl.target_path])

        if enumerate_imports:
            for candidate in self.idbctrl.enumerate_import_images():
                self.EChooser.addItem(list(candidate))
        if enumerate_other:
            for candidate in self.idbctrl.enumerate_files(recursive=self.chkDecompileImportsRecursive.checked):
                self.EChooser.addItem(list(candidate))

    def OnButtonProcess(self, code=0):
        ### process selected files
        if not len(list(self.EChooser.getSelected())):
            logger.warning("[!] Aborting. Please select at least one item from the list!")
            return

        self.idbctrl.target = self.target.value
        outputPath = self.GetControlValue(self.outputPath)
        if outputPath == '' or os.path.exists(outputPath):
            self.idbctrl.output_path = outputPath
        else:
            logger.warning("[!!] output path not valid! %r" % outputPath)
            self.idbctrl.output_path = None

        self.idbctrl.chk_annotate_stackvar_size = self.chkAnnotateStackVars.checked
        self.idbctrl.chk_decompile_imports = self.chkDecompileImports.checked
        self.idbctrl.chk_decompile_imports_recursive = self.chkDecompileImportsRecursive.checked
        self.idbctrl.chk_annotate_xrefs = self.chkAnnotateXrefs.checked
        self.idbctrl.chk_decompile_alternative = self.chkDecompileAlternative.checked
        logger.debug("[+] config updated")

        files_decompiled = []
        decompile_main_binary = False

        self.idbctrl.init_tempdir()
        for _type, name, image_path in self.EChooser.getSelected():
            if image_path is self.idbctrl.target_path:
                decompile_main_binary = True
                continue
            try:
                self.idbctrl.exec_ida_batch_decompile(target=image_path, output=outputPath,
                                              annotate_stackvar_size=self.idbctrl.chk_annotate_stackvar_size,
                                              annotate_xrefs=self.idbctrl.chk_annotate_xrefs,
                                              imports=self.idbctrl.chk_decompile_imports,
                                              recursive=self.idbctrl.chk_decompile_imports_recursive,
                                              experimental_decomile_cgraph=self.idbctrl.chk_decompile_alternative)
                files_decompiled.append(image_path)
            except subprocess.CalledProcessError, cpe:
                logger.warning("[!] failed to decompile %r - %r" % (image_path, cpe))

        self.idbctrl.remove_tempdir()
        ## process current file
        if decompile_main_binary:
            # well, loop here even though we know it can only
            logger.debug("[+] decompiling current file...")
            files_decompiled += self.idbctrl.run()  # decompile main binary
            logger.info("[+] finished decompiling: %r" % files_decompiled)
            logger.info("    output dir: %s" % self.idbctrl.output_path if self.idbctrl.output_path else self.idbctrl.target_dir)

    def OnButtonLoad(self, code=0):
        self.Close(0)
        self.propagateItems(enumerate_other=True, enumerate_imports=True)
        self.Execute()

    def OnFormChange(self, fid):
        # Set initial state
        INIT = -1
        BTN_OK = -2

        if fid == INIT:
            self.EnableField(self.target, False)
            self.EnableField(self.outputPath, True)
            self.EnableField(self.chkDecompileAlternative, False)

        elif fid == BTN_OK:
            # just return
            return True

        # Toggle backup checkbox
        elif fid == self.chkAnnotateStackVars.id:
            self.chkAnnotateStackVars.checked = not self.chkAnnotateStackVars.checked
        elif fid == self.chkDecompileImports.id:
            self.chkDecompileImports.checked = not self.chkDecompileImports.checked
        elif fid == self.chkDecompileImportsRecursive.id:
            self.chkDecompileImportsRecursive.checked = not self.chkDecompileImportsRecursive.checked
        elif fid == self.chkDecompileAlternative.id:
            self.chkDecompileAlternative.checked = not self.chkDecompileAlternative.checked
        elif fid == self.chkAnnotateXrefs.id:
            self.chkAnnotateXrefs.checked = not self.chkAnnotateXrefs.checked

        return False


if idaapi.IDA_SDK_VERSION >= 700:
    class IdaDecompileUiActionHandler(idaapi.action_handler_t):

        def __init__(self, caller):
            idaapi.action_handler_t.__init__(self)
            self.caller = caller

        def activate(self, ctx):
            self.caller.menu_config()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS


class IdaDecompileBatchPlugin(idaapi.plugin_t):
    """ IDA Plugin Base"""
    flags = idaapi.PLUGIN_FIX
    comment = "Batch Decompile"
    help = "github.com/tintinweb"
    wanted_name = "Ida Batch Decompile"
    wanted_hotkey = ""
    wanted_menu = "File/Produce file/", "{} ...".format(wanted_name)
    wanted_menu_id = 'tintinweb:batchdecompile'

    def init(self):
        NO_HOTKEY = ""
        SETMENU_INS = 0
        NO_ARGS = tuple()

        logger.debug("[+] %s.init()" % self.__class__.__name__)
        self.menuitems = []

        logger.debug("[+] setting up menus for ida version %s" % idaapi.IDA_SDK_VERSION)

        if idaapi.IDA_SDK_VERSION >= 700:
            # >= 700
            action_desc = idaapi.action_desc_t("tintinweb:batchdecompile:load", self.wanted_name, IdaDecompileUiActionHandler(self))
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu(''.join(self.wanted_menu), "tintinweb:batchdecompile:load", idaapi.SETMENU_APP)

        else:
            menu = idaapi.add_menu_item(self.wanted_menu[0],
                                        self.wanted_menu[1],
                                        NO_HOTKEY,
                                        SETMENU_INS,
                                        self.menu_config,
                                        NO_ARGS)

            self.menuitems.append(menu)

        return idaapi.PLUGIN_KEEP

    def run(self, arg=None):
        logger.debug("[+] %s.run()" % self.__class__.__name__)

    def term(self):
        logger.debug("[+] %s.term()" % self.__class__.__name__)
        if idaapi.IDA_SDK_VERSION < 700:
            for menu in self.menuitems:
                idaapi.del_menu_item(menu)

    def menu_config(self):
        logger.debug("[+] %s.menu_config()" % self.__class__.__name__)
        self.idbctrl._init_target() # force target reinit
        DecompileBatchForm(self.idbctrl).Execute()

    def set_ctrl(self, idbctrl):
        logger.debug("[+] %s.set_ctrl(%r)" % (self.__class__.__name__, idbctrl))
        self.idbctrl = idbctrl


def PLUGIN_ENTRY(mode=None):
    """ check execution mode:

        a) as Plugin, return plugin object
        b) as script as part of a batch execution, do not spawn plugin object
     """
    logging.basicConfig(level=logging.DEBUG,
                        format="[%(name)s/%(process)s][%(levelname)-10s] [%(module)s.%(funcName)-14s] %(message)s")
    logger.setLevel(logging.DEBUG)
    # always wait for analysis to finish
    logger.debug("[+] initializing IdaDecompileBatchPlugin")
    # create our controller interface
    idbctrl = IdaDecompileBatchController()
    # parse cmdline
    if mode == '__main__':
        # cmdline mode
        if len(idc.ARGV) > 1:
            # cmdline batch mode
            logger.debug("[+] Mode: commandline")
            parser = OptionParser()
            parser.add_option("-o", "--output", dest="output",
                              help="output path")
            parser.add_option("-S", "--annotate-stackvar-size",
                              action="store_true", default=False,
                              help="Generate stack variable size annotations")
            parser.add_option("-X", "--annotate-xrefs",
                              action="store_true", default=False,
                              help="Generate xref annotations")
            parser.add_option("-I", "--imports",
                              action="store_true", default=False,
                              help="try to decompile files referenced in IAT")
            parser.add_option("-R", "--recursive",
                              action="store_true", default=False,
                              help="Recursive decompile files/imports")
            parser.add_option("-Z", "--experimental-decompile-cgraph",
                              action="store_true", default=False,
                              help="[experimental] decompile funcs referenced in calltree manually")

            options, args = parser.parse_args(idc.ARGV[1:])
            # set options
            idbctrl.output_path = options.output
            idbctrl.chk_annotate_stackvar_size = options.annotate_stackvar_size
            idbctrl.chk_annotate_xrefs = options.annotate_xrefs
            idbctrl.chk_decompile_imports = options.imports
            idbctrl.chk_decompile_imports_recursive = options.recursive
            idbctrl.chk_decompile_alternative = options.experimental_decompile_cgraph
            # set all the idbctrl checkboxes and files
            idbctrl.run()
            idc.Exit(0)
            # return

        logger.debug("[+] Mode: commandline w/o args")
        # PluginMode
        plugin = IdaDecompileBatchPlugin()
        plugin.set_ctrl(idbctrl=idbctrl)
        plugin.init()
        logger.info("[i] %s loaded, see Menu: %s" % (IdaDecompileBatchPlugin.wanted_name,
                                                     IdaDecompileBatchPlugin.wanted_menu))
        #plugin.menu_config()
        return plugin

    else:
        logger.debug("[+] Mode: plugin")
        # PluginMode
        plugin = IdaDecompileBatchPlugin()
        plugin.set_ctrl(idbctrl=idbctrl)
        return plugin


if __name__ == '__main__':
    PLUGIN_ENTRY(mode=__name__)

