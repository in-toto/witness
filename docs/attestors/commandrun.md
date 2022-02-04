# Command Attestor

The command attestor collects information about a command that witness executes and observes.
The command's arguments, exit code, stdout, and stderr will be collected and added to the attestation.
Witness can optionally trace the command which will record all subprocesses started by the parent process
as well as all files opened by all processes. Please note that tracing is currently only supported on
Linux operating systems and is considered experimental for now.
