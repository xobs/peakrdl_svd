# PeakRDL SVD Importer

Import SVD files into PeakRDL for use with nice SVD display.

## Usage

```sh
python -mvenv .
. bin/activate
pip install peakrdl
peakrdl html STM32F429.svd -o html_dir
```

Or, using uvx:

```
uvx --from peakrdl-cli -w python-packages-are-weird -w peakrdl_html peakrdl html STM32F429.svd -o html_dir
```

Note that things are under a directory called `python-packages-are-weird` because apparently they can't be in the current directory, and some directories like `lib` appear to be special.