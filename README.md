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



//github.com/tintinweb
