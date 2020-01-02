# Memory-Tools
A program that provides a series a tools specially designed to manipulate process memory in interesting ways. Built and tested on Windows 10. The downloads can be found [here](https://github.com/Delkarix/Memory-Tools/releases).

> **If you discover any bugs, do not hesitate to report them to me in through the Issues tab.**


> **NOTE**: This repository is a recreation of my old one. While experimenting with another one of my programs (`Peter Griffin`), the Visual Studio files became corrupted and the application completely broke.

## Current Features
### Memory Corruptor
  * Frameshift (takes a range of bytes and shifts each byte onto the memory address before it).
  * Byte Randomization (takes a range of bytes and changes each byte to a random value).
  * Byte Incrementation (takes a range of bytes and adds 1 to each byte).
  * Byte Decrementation (takes a range of bytes and subtracts 1 from each byte).
 > Has interesting effects on games that use Procedural Generation (e.g. SCP Containment Breach) and Random Generation (e.g. Minecraft).

### Process Manipulator
* Window Painter
  * Allows you to draw colored pixels on a window.
* Control Injector
  * Allows you to create a Windows Control (Button, Label, Textbox, etc.) in another window.
* Thread Manager
  * Allows you to manipulate the data of a thread.
  
### Code Injector
* DLL Injector
  * Allows you to inject DLLs into a process.
* Bytecode Writer
  * Writes bytedata from a binary file into the address space of another process.
* Bytecode Reader
  * Reads a block of memory from a process and writes it to a binary file.
* Function Injector
  * Invokes a function located in the address space of the target process.
  
## I do not take responsibility for any damage that occurs through the usage of this program. USE AT YOUR OWN RISK.

# Usage
## Memory Corruptor
1. Click on the process button within the **Selected Process** groupbox.
2. After some time, a dialog box will appear with a list of processes. If the desired process does not appear, try pressing the **Refresh** button. If it still does not work, ensure that the process is running. If it does not work after this, try running the program as Administrator.
3. Select the desired process and click **OK**.
4. The dialog will close. On the left-hand side of the `Memory Corruptor` tab, you will see a list of Process Modules in the tree. You can click on the arrows to see the respective Memory Sections. You can view the properties of these by clicking on the arrows. From there, you can see the Base Address, End Address, Byte Size, Raw Base Address, Raw End Address, Raw Byte Size, and Data Flags.
> Note: The Base Address, End Address, Raw Base Address, and Raw End Address properties will only be displayed in Hexidecimal form.
5. Enter in the desired Base Address and End Address into the fields on the right-hand side of the window.
6. Select the desired type of corruption from the radio buttons on the right-hand side of the screen. The default is Frameshift
7. Click the Green button with the triangle. It should change to a Red button with a square. This will display corruption results in the Output Window. You can press the button again to pause the corruption.

### Supported Modes
* Frameshift Bytes
    + Takes a range of bytes and shifts them by 1.
* Randomize Bytes
    + Replaces each byte with a random value.
* Increment Bytes
    + Adds 1 to each byte.
* Decrement Bytes
    + Subtracts 1 from each byte.

## Process Manipulator
1. Click on the process button within the **Selected Process** groupbox.
2. After some time, a dialog box will appear with a list of processes. If the desired process does not appear, try pressing the **Refresh** button. If it still does not work, ensure that the process is running. If it does not work after this, try running the program as Administrator.
3. Select the desired process and click **OK**.
4. The dialog will close. From there, you can use any of the tools provided below.

#### Process Painter
1. Click on **Current Color** to change the color. 
2. Press the Green Button with the triangle.
3. Move your mouse over to the target process main window. The colors will be painted on as pixels.

#### Control Injector
1. Enter the x and y locations that the control will be placed at. The grid origin (0, 0) starts in the upper left-hand corner and ends in the lower right-hand corner (width, height).
2. Enter the width and height of the control.
3. Enter the text of the control.
4. Click on the drop-down menu to select the desired type of control. The default is a Button.
5. Click **Inject Control** to create the control in the other window.
> **NOTE**: All controls are given default (pre-Windows XP) stylizations. The styles cannot be changed, no events can or will be thrown, and properties cannot be changed. This may change in the future. When Memory Tools is closed, the controls that were injected will also be detached and deleted.

#### Thread Manager
1. Select the desired thread from the list. You can press **Reload** to update the list if you know a thread starts up or aborts.
> **NOTE**: The main thread is usually the first item on the list.
2. Click **Properties**. A window will be displayed indicating the list of CPU registers used by the process. You can change the values by editing the next.
> **NOTE**: The numeric system is `Hexidecimal`. If the desired text is not in Hexidecimal format, the text will turn red indicating that it must be changed.

> **NOTE**: If you want to execute code without utilizing DLL injections, it is a good idea to use the **Function Injector** to inject the `gets` function. The `gets` function is a default C/C++ function that forces a thread to pause and wait for input. A parameter is required, but it can be anything. Locate the thread in the thread list (you might need to click **Reload**) and change the `Current Instruction` field to the address of a desired function. If you wish to hijack a thread, locate the desired thread and suspend it. Then, change the `Current Instruction` field to the address of the desired function. Thread Hijacking is highly volatile and great care should be taken.

## Code Injector
1. Click on the process button within the **Selected Process** groupbox.
2. After some time, a dialog box will appear with a list of processes. If the desired process does not appear, try pressing the **Refresh** button. If it still does not work, ensure that the process is running. If it does not work after this, try running the program as Administrator.
3. Select the desired process and click **OK**.
4. The dialog will close. From there, you use any of the tools provided below.

#### DLL Injector
1. Click on "Select DLL". This will show a window where you can select DLL Files and inject. You can press `CTRL` to select multiple.
2. Click **OK**.
3. You can press "Remove DLL" to remove the selected DLL. You can press "Reset List" to remove all of the DLLs.
4. Press "Inject DLLs" to inject the DLLs into the process. When the DLLs are injected, all code in their `DllMain` method will execute in the target process's address space.

#### Function Injector
1. Ensure that the desired function is available inside of the target process. If your desired function comes from a DLL, inject the DLL first.
2. Enter the name of the desired function.
3. Enter optional parameters. Check the "Integer" box if the desired type is numerical. Otherwise, it will be represented as a string.
4. Click the "Inject Function" button.

#### Bytecode Writer
1. Click on "Open File" to open a binary file. If successful, the output window will display magenta text saying that the file was loaded successfully.
2. Designate the Base Address of injection. If the Base Address is unknown or a generated Base Address is desired, check the "Allocate Memory" checkbox.
3. Click "Inject".

#### Bytecode Reader
1. Specify the Base Address and End Address fields. The Base Address must not be larger than the End Address.
2. Click "Save File"
