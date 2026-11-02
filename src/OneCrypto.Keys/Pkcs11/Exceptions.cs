using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>
/// The return values (CK_RV) a module reports, PKCS #11 v3.1 §5.1. Only the values the library
/// reacts to are named; any other value a module returns is carried as its number in <see cref="Pkcs11Exception.ReturnCode"/>.
/// </summary>
public enum Pkcs11Result : uint
{
    /// <summary>CKR_OK.</summary>
    Ok = 0x00,
    /// <summary>CKR_CANT_LOCK.</summary>
    CantLock = 0x0A,
    /// <summary>CKR_GENERAL_ERROR.</summary>
    GeneralError = 0x05,
    /// <summary>CKR_FUNCTION_FAILED.</summary>
    FunctionFailed = 0x06,
    /// <summary>CKR_ARGUMENTS_BAD.</summary>
    ArgumentsBad = 0x07,
    /// <summary>CKR_ATTRIBUTE_SENSITIVE.</summary>
    AttributeSensitive = 0x11,
    /// <summary>CKR_ATTRIBUTE_TYPE_INVALID.</summary>
    AttributeTypeInvalid = 0x12,
    /// <summary>CKR_DATA_INVALID.</summary>
    DataInvalid = 0x20,
    /// <summary>CKR_DATA_LEN_RANGE.</summary>
    DataLenRange = 0x21,
    /// <summary>CKR_DEVICE_ERROR.</summary>
    DeviceError = 0x30,
    /// <summary>CKR_DEVICE_REMOVED.</summary>
    DeviceRemoved = 0x32,
    /// <summary>CKR_ENCRYPTED_DATA_INVALID.</summary>
    EncryptedDataInvalid = 0x40,
    /// <summary>CKR_ENCRYPTED_DATA_LEN_RANGE.</summary>
    EncryptedDataLenRange = 0x41,
    /// <summary>CKR_FUNCTION_NOT_SUPPORTED.</summary>
    FunctionNotSupported = 0x54,
    /// <summary>CKR_KEY_HANDLE_INVALID.</summary>
    KeyHandleInvalid = 0x60,
    /// <summary>CKR_KEY_SIZE_RANGE.</summary>
    KeySizeRange = 0x62,
    /// <summary>CKR_KEY_TYPE_INCONSISTENT.</summary>
    KeyTypeInconsistent = 0x63,
    /// <summary>CKR_KEY_FUNCTION_NOT_PERMITTED.</summary>
    KeyFunctionNotPermitted = 0x68,
    /// <summary>CKR_MECHANISM_INVALID.</summary>
    MechanismInvalid = 0x70,
    /// <summary>CKR_MECHANISM_PARAM_INVALID.</summary>
    MechanismParamInvalid = 0x71,
    /// <summary>CKR_OBJECT_HANDLE_INVALID.</summary>
    ObjectHandleInvalid = 0x82,
    /// <summary>CKR_OPERATION_ACTIVE.</summary>
    OperationActive = 0x90,
    /// <summary>CKR_PIN_INCORRECT.</summary>
    PinIncorrect = 0xA0,
    /// <summary>CKR_PIN_INVALID.</summary>
    PinInvalid = 0xA1,
    /// <summary>CKR_PIN_LEN_RANGE.</summary>
    PinLenRange = 0xA2,
    /// <summary>CKR_PIN_EXPIRED.</summary>
    PinExpired = 0xA3,
    /// <summary>CKR_PIN_LOCKED.</summary>
    PinLocked = 0xA4,
    /// <summary>CKR_SESSION_CLOSED.</summary>
    SessionClosed = 0xB0,
    /// <summary>CKR_SESSION_HANDLE_INVALID.</summary>
    SessionHandleInvalid = 0xB3,
    /// <summary>CKR_SESSION_READ_ONLY.</summary>
    SessionReadOnly = 0xB5,
    /// <summary>CKR_SIGNATURE_INVALID.</summary>
    SignatureInvalid = 0xC0,
    /// <summary>CKR_SIGNATURE_LEN_RANGE.</summary>
    SignatureLenRange = 0xC1,
    /// <summary>CKR_TEMPLATE_INCOMPLETE.</summary>
    TemplateIncomplete = 0xD0,
    /// <summary>CKR_TEMPLATE_INCONSISTENT.</summary>
    TemplateInconsistent = 0xD1,
    /// <summary>CKR_TOKEN_NOT_PRESENT.</summary>
    TokenNotPresent = 0xE0,
    /// <summary>CKR_TOKEN_NOT_RECOGNIZED.</summary>
    TokenNotRecognized = 0xE1,
    /// <summary>CKR_TOKEN_WRITE_PROTECTED.</summary>
    TokenWriteProtected = 0xE2,
    /// <summary>CKR_USER_ALREADY_LOGGED_IN.</summary>
    UserAlreadyLoggedIn = 0x100,
    /// <summary>CKR_USER_NOT_LOGGED_IN.</summary>
    UserNotLoggedIn = 0x101,
    /// <summary>CKR_USER_PIN_NOT_INITIALIZED.</summary>
    UserPinNotInitialized = 0x102,
    /// <summary>CKR_BUFFER_TOO_SMALL.</summary>
    BufferTooSmall = 0x150,
    /// <summary>CKR_CRYPTOKI_NOT_INITIALIZED.</summary>
    CryptokiNotInitialized = 0x190,
    /// <summary>CKR_CRYPTOKI_ALREADY_INITIALIZED.</summary>
    CryptokiAlreadyInitialized = 0x191,
}

/// <summary>
/// A PKCS #11 call failed, or something the module returned could not be used. Every failure of this backend is one of the subclasses
/// (<see cref="Pkcs11ModuleException"/>, <see cref="Pkcs11TokenException"/>, <see cref="Pkcs11PinException"/>, <see cref="Pkcs11KeyException"/>,
/// <see cref="Pkcs11MechanismException"/>); the raw module return value is kept in <see cref="ReturnCode"/> for logs and is never the only information.
/// It derives from <see cref="CryptographicException"/> so callers that already handle key failures need no new catch.
/// </summary>
public class Pkcs11Exception : CryptographicException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What failed, in a sentence.</param>
    /// <param name="function">The PKCS #11 function that reported it, for example <c>C_Login</c>; empty when none did.</param>
    /// <param name="returnCode">The CK_RV value the module returned, or null when the failure was not a module return value.</param>
    public Pkcs11Exception(string message, string function = "", uint? returnCode = null)
        : base(message)
    {
        Function = function;
        ReturnCode = returnCode;
    }

    /// <summary>The PKCS #11 function that reported the failure (for example <c>C_Sign</c>), or empty.</summary>
    public string Function { get; }

    /// <summary>The CK_RV the module returned, or null if the failure did not come from a module return value.</summary>
    public uint? ReturnCode { get; }

    /// <summary>The return value as a <see cref="Pkcs11Result"/> (compare with the named values; other values are carried as their number), or null.</summary>
    public Pkcs11Result? Result => ReturnCode is uint v ? (Pkcs11Result)v : null;
}

/// <summary>
/// The module could not be loaded or initialised: the path does not exist, the file is not a PKCS #11 module (no <c>C_GetFunctionList</c>), it is for
/// another architecture, <c>C_Initialize</c> failed, or this platform is not supported (the backend needs a 64-bit Unix platform).
/// </summary>
public sealed class Pkcs11ModuleException : Pkcs11Exception
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11ModuleException(string message, string function = "", uint? returnCode = null, string? modulePath = null)
        : base(message, function, returnCode)
    {
        ModulePath = modulePath;
    }

    /// <summary>The module path that was asked for, when known.</summary>
    public string? ModulePath { get; }
}

/// <summary>The token or slot cannot be used right now: absent or removed, session closed, a device error, or the module was disposed.</summary>
public sealed class Pkcs11TokenException : Pkcs11Exception
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11TokenException(string message, string function = "", uint? returnCode = null)
        : base(message, function, returnCode)
    {
    }
}

/// <summary>The PIN was refused: wrong (<see cref="Pkcs11Exception.Result"/> is <see cref="Pkcs11Result.PinIncorrect"/>), of an impossible length, expired, or no PIN was given.</summary>
public class Pkcs11PinException : Pkcs11Exception
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11PinException(string message, string function = "", uint? returnCode = null)
        : base(message, function, returnCode)
    {
    }
}

/// <summary>The user PIN is locked after too many wrong attempts; only the security officer can unblock it. The library never retries a PIN by itself.</summary>
public sealed class Pkcs11PinLockedException : Pkcs11PinException
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11PinLockedException(string message, string function = "", uint? returnCode = null)
        : base(message, function, returnCode)
    {
    }
}

/// <summary>A key or certificate object is missing, ambiguous, was removed from the token, or may not be used for the operation.</summary>
public sealed class Pkcs11KeyException : Pkcs11Exception
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11KeyException(string message, string function = "", uint? returnCode = null)
        : base(message, function, returnCode)
    {
    }
}

/// <summary>
/// The token does not know the mechanism, or refused its parameters (CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID). The key interfaces
/// report a mechanism the token's list lacks as <see cref="AlgorithmNotSupportedException"/> before calling the token; this exception is for the
/// low-level <see cref="Pkcs11Session"/> calls and for a token that lists a mechanism and then refuses it.
/// </summary>
public sealed class Pkcs11MechanismException : Pkcs11Exception
{
    /// <summary>Creates the exception.</summary>
    public Pkcs11MechanismException(string message, string function = "", uint? returnCode = null)
        : base(message, function, returnCode)
    {
    }
}

internal static class Pkcs11Errors
{
    /// <summary>Maps a module return value to the typed exception that explains it.</summary>
    internal static string Name(nuint rv)
    {
        uint v = unchecked((uint)rv);
        return Enum.IsDefined((Pkcs11Result)v) ? ((Pkcs11Result)v).ToString() : "0x" + v.ToString("X", System.Globalization.CultureInfo.InvariantCulture);
    }

    internal static Pkcs11Exception For(string function, nuint rv)
    {
        uint v = unchecked((uint)rv);
        string name = Name(rv);
        string text = $"{function} failed: {name}";
        // CKR_ARGUMENTS_BAD from an operation's Init call is a refused mechanism parameter (for example an OAEP hash the token lacks), not a caller bug.
        if ((Pkcs11Result)v == Pkcs11Result.ArgumentsBad && function.EndsWith("Init", StringComparison.Ordinal))
        {
            return new Pkcs11MechanismException(text + ". The token refused the mechanism's parameters.", function, v);
        }

        return (Pkcs11Result)v switch
        {
            Pkcs11Result.PinLocked => new Pkcs11PinLockedException(text + ". The PIN is locked.", function, v),
            Pkcs11Result.PinIncorrect or Pkcs11Result.PinInvalid or Pkcs11Result.PinLenRange or Pkcs11Result.PinExpired
                => new Pkcs11PinException(text, function, v),
            Pkcs11Result.MechanismInvalid or Pkcs11Result.MechanismParamInvalid => new Pkcs11MechanismException(text, function, v),
            Pkcs11Result.TokenNotPresent or Pkcs11Result.TokenNotRecognized or Pkcs11Result.DeviceRemoved or Pkcs11Result.DeviceError
                or Pkcs11Result.SessionClosed or Pkcs11Result.SessionHandleInvalid or Pkcs11Result.CryptokiNotInitialized
                or Pkcs11Result.TokenWriteProtected or Pkcs11Result.SessionReadOnly
                => new Pkcs11TokenException(text, function, v),
            Pkcs11Result.ObjectHandleInvalid or Pkcs11Result.KeyHandleInvalid or Pkcs11Result.KeyFunctionNotPermitted
                or Pkcs11Result.KeyTypeInconsistent or Pkcs11Result.KeySizeRange
                => new Pkcs11KeyException(text, function, v),
            Pkcs11Result.UserNotLoggedIn => new Pkcs11PinException(text + ". The token needs a login for this key.", function, v),
            _ => new Pkcs11Exception(text, function, v),
        };
    }
}
