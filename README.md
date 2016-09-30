# ida-batch_decompile

*Decompile all the things!* *(Work in progress)*

IDA Batch Decompile is a plugin for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file


# Usage

## idascript (gui mode)

1. open target, wait for analysis to finish
2. `IDA Pro -> File/Script file... -> <this_python_script>`
3. `IDA Pro -> File/Produce file-> IdaDecompileBatch ...`
3. tick `Annotate StackVarSize`, `Annotate Func XRefs`
4. click `OK` to decompile.

Note: File will be saved in target folder as `<target_image_name.c>`

## idascript (cmdline batch mode)

    <path_to_ida>/ida(w|w64)(.exe) -B -M -S"<path_to_this_script> \"--option1\" \"--option2\"", "<target>"`

Note that options need to be quoted with `\"`

Available options, see `--help`

    --output                        ... output file path
    --annotate-stackvar-size        ... annotate function stack variable sizes
    --annotate-xrefs                ... annotate function xrefs
    --imports                       ... process imports
    --recursive                     ... recursive batch decompile
    --experimental-decompile-cgraph ... experimental: manually decompile function call graph

## Ida Plugin

1. Follow the IDA Pro documentation on how to add python plugins.
2. `IDA Pro -> File/Produce file -> IdaDecompileBatch ...`

# run

### ida console: decompiling dbghelp.dll

```python
[__main__/36908][DEBUG     ] [idabatchdecompile.PLUGIN_ENTRY  ] [+] initializing IdaDecompileBatchPlugin
[__main__/36908][DEBUG     ] [idabatchdecompile.__init__      ] [+] is_windows: True
[__main__/36908][DEBUG     ] [idabatchdecompile.__init__      ] [+] is_ida64: False
[__main__/36908][DEBUG     ] [idabatchdecompile.wait_for_analysis_to_finish] [+] waiting for analysis to finish...
[__main__/36908][DEBUG     ] [idabatchdecompile.wait_for_analysis_to_finish] [+] analysis finished.
[__main__/36908][DEBUG     ] [idabatchdecompile.load_plugin_decompiler] [+] trying to load decompiler plugins
[__main__/36908][DEBUG     ] [idabatchdecompile.load_plugin_decompiler] [+] decompiler plugins loaded.
[__main__/36908][DEBUG     ] [idabatchdecompile.PLUGIN_ENTRY  ] [+] Mode: commandline w/o args
[__main__/36908][DEBUG     ] [idabatchdecompile.set_ctrl      ] [+] IdaDecompileBatchPlugin.set_ctrl(<__main__.IdaDecompileBatchController object at 0x056FCF90>)
[__main__/36908][DEBUG     ] [idabatchdecompile.init          ] [+] IdaDecompileBatchPlugin.init()
[__main__/36908][DEBUG     ] [idabatchdecompile.init          ] [+] setting up menus
[__main__/36908][INFO      ] [idabatchdecompile.PLUGIN_ENTRY  ] [i] IdaDecompileBatch loaded, see Menu: ('File/Produce file/', 'IdaDecompileBatch ...')
...
 The application has been completely decompiled.
[__main__/36908][DEBUG     ] [idabatchdecompile.decompile_all ] [+] finished decompiling 'dbghelp.dll' as 'dbghelp.c'
```

### annotated pseudocode: dbghelp.c

```c
//----- (03052800) --------------------------------------------------------
// **** Variables ****
// * stack size: 20
// {"diff_size": 4, "offset_text": "[bp+0h]", "size": 4, "name": " s", "offset": 0}
// {"diff_size": 4, "offset_text": "[bp+4h]", "size": 4, "name": " r", "offset": 4}
// {"diff_size": 4, "offset_text": "[bp+8h]", "size": 4, "name": "arg_0", "offset": 8}
// {"diff_size": 4, "offset_text": "[bp+Ch]", "size": 4, "name": "dwBytes", "offset": 12}
// {"diff_size": 4, "offset_text": "[bp+10h]", "size": 4, "name": "arg_8", "offset": 16}
// *******************
// ***** XREFS *****
// * # 1
// sub_30733D0+30
// *******************
int __stdcall sub_3052800(int a1, SIZE_T dwBytes, int a3)
{
  int result; // eax@17
  HANDLE v4; // eax@21
...
```


//github.com/tintinweb
