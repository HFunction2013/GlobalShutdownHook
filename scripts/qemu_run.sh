#!/bin/bash
# ============================================================
#  QEMU Launch Script for GlobalShutdownHook Testing
#
#  Prerequisites:
#    - qemu-system-x86_64 installed
#    - A Windows 10/11 x64 disk image (win11.qcow2)
#    - OVMF firmware (for UEFI boot)
#
#  Usage:
#    1. First time: create a disk image and install Windows
#    2. Edit the variables below to match your setup
#    3. Run: ./qemu_run.sh
#
#  Debugging:
#    Serial pipe is exposed for WinDbg kernel debugging.
#    In WinDbg: File -> Kernel Debug -> COM -> Baud 115200
# ============================================================

set -e

# ---- Configuration (edit these) ----
VM_NAME="Win11-GSH-Test"
DISK_IMAGE="win11.qcow2"
DISK_SIZE="64G"
RAM="4096"
CPU_CORES="4"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
OVMF_VARS="OVMF_VARS.fd"
SHARED_DIR="./shared"          # Shared folder with the built driver
SERIAL_PIPE="/tmp/gsh_serial" # Named pipe for kernel debugger

# ---- Create shared directory if needed ----
mkdir -p "$SHARED_DIR"

# ---- Create OVMF vars copy (first time) ----
if [ ! -f "$OVMF_VARS" ]; then
    if [ -f "/usr/share/OVMF/OVMF_VARS.fd" ]; then
        cp "/usr/share/OVMF/OVMF_VARS.fd" "$OVMF_VARS"
    else
        echo "WARNING: OVMF_VARS.fd not found. UEFI boot may fail."
        echo "Install OVMF: sudo apt install ovmf"
    fi
fi

# ---- Create disk image (first time) ----
if [ ! -f "$DISK_IMAGE" ]; then
    echo "Creating disk image $DISK_IMAGE ($DISK_SIZE)..."
    qemu-img create -f qcow2 "$DISK_IMAGE" "$DISK_SIZE"
    echo "Disk image created. Install Windows first, then re-run this script."
    echo "To install: add -cdrom /path/to/windows.iso -boot d to the qemu command."
    exit 0
fi

# ---- Clean up old serial pipe ----
rm -f "$SERIAL_PIPE"
mkfifo "$SERIAL_PIPE"

echo "============================================================"
echo "  Starting VM: $VM_NAME"
echo "  Disk:   $DISK_IMAGE"
echo "  RAM:    ${RAM}MB"
echo "  CPUs:   $CPU_CORES"
echo "  Shared: $SHARED_DIR  (mount as network drive in VM)"
echo "  Serial: $SERIAL_PIPE  (for WinDbg kernel debug)"
echo "============================================================"
echo ""
echo "Tip: In the VM, open cmd as admin and:"
echo "  bcdedit /set testsigning on"
echo "  (reboot)"
echo "  Then copy driver from shared folder and run install_and_test.bat"
echo ""

# ---- Launch QEMU ----
qemu-system-x86_64 \
    -name "$VM_NAME" \
    -machine q35,accel=kvm \
    -cpu host \
    -smp "$CPU_CORES" \
    -m "$RAM" \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -drive file="$DISK_IMAGE",format=qcow2,if=virtio \
    -net nic,model=virtio \
    -net user,smb="$SHARED_DIR",smbserver=10.0.2.4 \
    -chardev pipe,id=charserial0,path="$SERIAL_PIPE" \
    -device isa-serial,chardev=charserial0,id=serial0 \
    -usb \
    -device usb-tablet \
    -vga virtio \
    -display gtk \
    -boot order=c \
    "$@"

echo ""
echo "VM stopped. Cleaning up..."
rm -f "$SERIAL_PIPE"
