Project Description:

This tool implements an automated approach for extracting unpacked images of executable files (EXE) and dynamic-link libraries (DLL) directly from a process’s memory. The method is based on controlling the lifecycle of the target process: it is created in a suspended state, hooks are placed on key API functions, and then execution is resumed. Once the unpacking stage is completed, the fully unpacked image is dumped from memory.

The tool can be used for research and analytical purposes, including:
  1. studying software behavior;
  2. analyzing protected packers and obfuscators;
  3. performing static and dynamic reverse engineering of binary modules.

Key Features

  1. Operates entirely in user mode.
  
  2. Unified mechanism for both EXE and DLL unpacking.
  
  3. Uses API hooks to track loading and unpacking stages.
  
  4. Minimal interference with the target process to ensure dump correctness.
  
  5. Tested on popular commercial protectors, including Themida and VMProtect.
