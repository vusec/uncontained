# Dataflow Viewer Visual Studio Code Extension

This is an extension to look at the results from the SimpleDataflowChecker pass.
The reports are returned in the YAML format and are by default located within the used linux repository.

## How to install

First ensure you are running on a machine with vscode installed.
Then install the extension:
```
code --install-extension dataflowviewer-0.0.1.vsix
```
or install it from within vscode by selecting `Install from VSIX...`.

## How to use

* Open the `uncontained-linux` repository in vscode and make sure the `reports.yaml` is located in the root directory.
* Click on "Parse Report File" and select the `reports.yaml`.
* Bugs are sorted by the rule they generated and the total amount (grouped by source line) is shown next to it.
* You can use the 'Demote' and 'FP' button to classify the bugs.
* To save the analysis you can select "Export Analysis To File" from the menu and save it including the classification.
* The exported YAML can be reloaded into the extension to restore the previous classification.

## How to build

Run the following commands to rebuild the extension if you did changes:
```
npm install -g vsce
vsce package
```

Now you can install the updated vsix file again.
