# IR Matters: Where the features come from affects cross-architecture binary code similarity detection

This repo provides an implementation of the Gemini-IR [] based on [Gemini](https://github.com/xiaojunxu/dnn-binary-code-similarity).

ALL .py files are implemented with python3.7.3 with IDA Pro 7.5 (IDAPython with python3)

## Files structures
<pre>
│  .gitignore
│  batch_run_vex.py
│  count_block_nums.py
│  data_ori.zip
│  delete_idb.py
│  eval.py
│  features_extract_vex.py
│  features_get.py
│  gen_pyvex_ir.py
│  graphnnSiamese.py
│  joint_datasets.py
│  LICENSE
│  opcodes.py
│  plot_show.py
│  preprocessing_ida.py
│  preprocessing_ida_vex.py
│  README.md
│  requirements.txt
│  train.py
│  type.temp
│  utils.py
│  vex_opcode.py
</pre>

## Prepration and Data

Download the Gemini-IR and cross-tools from [here](https://drive.google.com/drive/folders/1H7c8XTchze4qxOFEFEbONsssXT-OMSb7) and extract them into corresponding directories.
Unzip the Gemini-IR by running:

```bash
unzip Gemini-IR.zip
```
The Gemini-IR.zip contains the elf cross-compiled (x86, mips, arm, ppc) by gccv5.4 and features extracted by IDA Pro and pyvex of openssl, binutils and coreutils.

Unzip the data by running:

```bash
unzip data.zip
```
The data.zip contains the `.json` files of features to be trained.

The cross-tools are built with [buildroot-2016.08](http://buildroot.net/downloads/).
To use the cross-compiler, you should remove the `staging` link, and add new link to the directory `[your path]/host/usr/powerpc-buildroot-linux-gnu/sysroot`
```bash
cd arm-5.4/host
rm staging
ln -sv /home/ghost/crosstool/arm-5.4/host/usr/armeb-buildroot-linux-uclibcgnueabi/sysroot staging
```


## Hints:
All python scripts are tested with IDA Pro 7.5 (IDAPython 3) and Python v3.7.3.
Before running the python scripts, you should set the `PATH` environment of `idat.exe` and the corresponding directories path in the python scripts.

### Extract the features from assembly instructions

<pre>
│  batch_run_vex.py
│  features_get.py
│  preprocessing_ida.py
│  opcodes.py
│  type.temp

</pre>

```bash
python batch_run_vex.py --lib=SSL --dele=1 --fea_dim=9
```

### Extract the features from IR instructions

<pre>
│  batch_run_vex.py
│  preprocessing_ida_vex.py
│  gen_pyvex_ir.py
│  features_extract_vex.py
│  vex_opcode.py
│  type.temp
</pre>

```bash
python batch_run_vex.py --lib=SSL_vex --dele=1 --fea_dim=9
```

The network is tested using Tensorflow 1.5 in Python 3.7.3. You can install the dependencies by running:
```bash
pip install -r requirements.txt
```

## Model Implementation
The model is implemented based on Gemini.

Run the following code to train the model:
```bash
python train.py --lib=Core_vex --fea_dim=9
```
or run `python train.py -h` to check the optional arguments.


After training, run the following code to evaluate the model:
```bash
python eval.py --lib=Core_vex --fea_dim=9
```
or run `python eval.py -h` to check the optional arguments.

## Results
The netowrk checkpoints are saved in `save_model` directory
The `"loss", "auc", "tpr", "fpr"` and so on are save in `res` directory
res

## Plot the AUC, Loss and ROC curves

```bash
python plot_show.py
```
The `.svg` files are saved in `res` directory.
## Count the Basic-block numbers of datasets

```bash
python count_block_nums.py
```
or run `python count_block_nums.py -h` to check the optional arguments.
