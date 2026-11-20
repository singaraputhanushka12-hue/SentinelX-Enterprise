import ctypes
import os


class DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def protect_data(data, protect):
    if os.name != "nt":
        raise RuntimeError("Encrypted connector storage requires Windows DPAPI.")

    input_buffer = ctypes.create_string_buffer(data)
    input_blob = DataBlob(
        len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    output_blob = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    if protect:
        operation = crypt32.CryptProtectData
        operation.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.c_wchar_p,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DataBlob),
        ]
        succeeded = operation(
            ctypes.byref(input_blob),
            "SentinelX LOGIN connector credentials",
            None,
            None,
            None,
            1,
            ctypes.byref(output_blob),
        )
    else:
        description = ctypes.POINTER(ctypes.c_wchar)()
        operation = crypt32.CryptUnprotectData
        operation.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_wchar)),
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DataBlob),
        ]
        succeeded = operation(
            ctypes.byref(input_blob),
            ctypes.byref(description),
            None,
            None,
            None,
            1,
            ctypes.byref(output_blob),
        )

    if not succeeded:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))
        if not protect and description:
            kernel32.LocalFree(ctypes.cast(description, ctypes.c_void_p))


