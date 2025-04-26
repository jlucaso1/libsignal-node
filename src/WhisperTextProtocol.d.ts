import * as $protobuf from "protobufjs";
import Long = require("long");
/** Properties of a SignalMessage. */
export interface ISignalMessage {

    /** SignalMessage ratchetKey */
    ratchetKey?: (Uint8Array|null);

    /** SignalMessage counter */
    counter?: (number|null);

    /** SignalMessage previousCounter */
    previousCounter?: (number|null);

    /** SignalMessage ciphertext */
    ciphertext?: (Uint8Array|null);
}

/** Represents a SignalMessage. */
export class SignalMessage implements ISignalMessage {

    /**
     * Constructs a new SignalMessage.
     * @param [properties] Properties to set
     */
    constructor(properties?: ISignalMessage);

    /** SignalMessage ratchetKey. */
    public ratchetKey: Uint8Array;

    /** SignalMessage counter. */
    public counter: number;

    /** SignalMessage previousCounter. */
    public previousCounter: number;

    /** SignalMessage ciphertext. */
    public ciphertext: Uint8Array;

    /**
     * Creates a new SignalMessage instance using the specified properties.
     * @param [properties] Properties to set
     * @returns SignalMessage instance
     */
    public static create(properties?: ISignalMessage): SignalMessage;

    /**
     * Encodes the specified SignalMessage message. Does not implicitly {@link SignalMessage.verify|verify} messages.
     * @param message SignalMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encode(message: ISignalMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Encodes the specified SignalMessage message, length delimited. Does not implicitly {@link SignalMessage.verify|verify} messages.
     * @param message SignalMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encodeDelimited(message: ISignalMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Decodes a SignalMessage message from the specified reader or buffer.
     * @param reader Reader or buffer to decode from
     * @param [length] Message length if known beforehand
     * @returns SignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): SignalMessage;

    /**
     * Decodes a SignalMessage message from the specified reader or buffer, length delimited.
     * @param reader Reader or buffer to decode from
     * @returns SignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): SignalMessage;

    /**
     * Verifies a SignalMessage message.
     * @param message Plain object to verify
     * @returns `null` if valid, otherwise the reason why it is not
     */
    public static verify(message: { [k: string]: any }): (string|null);

    /**
     * Creates a SignalMessage message from a plain object. Also converts values to their respective internal types.
     * @param object Plain object
     * @returns SignalMessage
     */
    public static fromObject(object: { [k: string]: any }): SignalMessage;

    /**
     * Creates a plain object from a SignalMessage message. Also converts values to other types if specified.
     * @param message SignalMessage
     * @param [options] Conversion options
     * @returns Plain object
     */
    public static toObject(message: SignalMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

    /**
     * Converts this SignalMessage to JSON.
     * @returns JSON object
     */
    public toJSON(): { [k: string]: any };

    /**
     * Gets the default type url for SignalMessage
     * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns The default type url
     */
    public static getTypeUrl(typeUrlPrefix?: string): string;
}

/** Properties of a PreKeySignalMessage. */
export interface IPreKeySignalMessage {

    /** PreKeySignalMessage registrationId */
    registrationId?: (number|null);

    /** PreKeySignalMessage preKeyId */
    preKeyId?: (number|null);

    /** PreKeySignalMessage signedPreKeyId */
    signedPreKeyId?: (number|null);

    /** PreKeySignalMessage baseKey */
    baseKey?: (Uint8Array|null);

    /** PreKeySignalMessage identityKey */
    identityKey?: (Uint8Array|null);

    /** PreKeySignalMessage message */
    message?: (Uint8Array|null);
}

/** Represents a PreKeySignalMessage. */
export class PreKeySignalMessage implements IPreKeySignalMessage {

    /**
     * Constructs a new PreKeySignalMessage.
     * @param [properties] Properties to set
     */
    constructor(properties?: IPreKeySignalMessage);

    /** PreKeySignalMessage registrationId. */
    public registrationId: number;

    /** PreKeySignalMessage preKeyId. */
    public preKeyId: number;

    /** PreKeySignalMessage signedPreKeyId. */
    public signedPreKeyId: number;

    /** PreKeySignalMessage baseKey. */
    public baseKey: Uint8Array;

    /** PreKeySignalMessage identityKey. */
    public identityKey: Uint8Array;

    /** PreKeySignalMessage message. */
    public message: Uint8Array;

    /**
     * Creates a new PreKeySignalMessage instance using the specified properties.
     * @param [properties] Properties to set
     * @returns PreKeySignalMessage instance
     */
    public static create(properties?: IPreKeySignalMessage): PreKeySignalMessage;

    /**
     * Encodes the specified PreKeySignalMessage message. Does not implicitly {@link PreKeySignalMessage.verify|verify} messages.
     * @param message PreKeySignalMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encode(message: IPreKeySignalMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Encodes the specified PreKeySignalMessage message, length delimited. Does not implicitly {@link PreKeySignalMessage.verify|verify} messages.
     * @param message PreKeySignalMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encodeDelimited(message: IPreKeySignalMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Decodes a PreKeySignalMessage message from the specified reader or buffer.
     * @param reader Reader or buffer to decode from
     * @param [length] Message length if known beforehand
     * @returns PreKeySignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): PreKeySignalMessage;

    /**
     * Decodes a PreKeySignalMessage message from the specified reader or buffer, length delimited.
     * @param reader Reader or buffer to decode from
     * @returns PreKeySignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): PreKeySignalMessage;

    /**
     * Verifies a PreKeySignalMessage message.
     * @param message Plain object to verify
     * @returns `null` if valid, otherwise the reason why it is not
     */
    public static verify(message: { [k: string]: any }): (string|null);

    /**
     * Creates a PreKeySignalMessage message from a plain object. Also converts values to their respective internal types.
     * @param object Plain object
     * @returns PreKeySignalMessage
     */
    public static fromObject(object: { [k: string]: any }): PreKeySignalMessage;

    /**
     * Creates a plain object from a PreKeySignalMessage message. Also converts values to other types if specified.
     * @param message PreKeySignalMessage
     * @param [options] Conversion options
     * @returns Plain object
     */
    public static toObject(message: PreKeySignalMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

    /**
     * Converts this PreKeySignalMessage to JSON.
     * @returns JSON object
     */
    public toJSON(): { [k: string]: any };

    /**
     * Gets the default type url for PreKeySignalMessage
     * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns The default type url
     */
    public static getTypeUrl(typeUrlPrefix?: string): string;
}

/** Properties of a KeyExchangeMessage. */
export interface IKeyExchangeMessage {

    /** KeyExchangeMessage id */
    id?: (number|null);

    /** KeyExchangeMessage baseKey */
    baseKey?: (Uint8Array|null);

    /** KeyExchangeMessage ratchetKey */
    ratchetKey?: (Uint8Array|null);

    /** KeyExchangeMessage identityKey */
    identityKey?: (Uint8Array|null);

    /** KeyExchangeMessage baseKeySignature */
    baseKeySignature?: (Uint8Array|null);
}

/** Represents a KeyExchangeMessage. */
export class KeyExchangeMessage implements IKeyExchangeMessage {

    /**
     * Constructs a new KeyExchangeMessage.
     * @param [properties] Properties to set
     */
    constructor(properties?: IKeyExchangeMessage);

    /** KeyExchangeMessage id. */
    public id: number;

    /** KeyExchangeMessage baseKey. */
    public baseKey: Uint8Array;

    /** KeyExchangeMessage ratchetKey. */
    public ratchetKey: Uint8Array;

    /** KeyExchangeMessage identityKey. */
    public identityKey: Uint8Array;

    /** KeyExchangeMessage baseKeySignature. */
    public baseKeySignature: Uint8Array;

    /**
     * Creates a new KeyExchangeMessage instance using the specified properties.
     * @param [properties] Properties to set
     * @returns KeyExchangeMessage instance
     */
    public static create(properties?: IKeyExchangeMessage): KeyExchangeMessage;

    /**
     * Encodes the specified KeyExchangeMessage message. Does not implicitly {@link KeyExchangeMessage.verify|verify} messages.
     * @param message KeyExchangeMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encode(message: IKeyExchangeMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Encodes the specified KeyExchangeMessage message, length delimited. Does not implicitly {@link KeyExchangeMessage.verify|verify} messages.
     * @param message KeyExchangeMessage message or plain object to encode
     * @param [writer] Writer to encode to
     * @returns Writer
     */
    public static encodeDelimited(message: IKeyExchangeMessage, writer?: $protobuf.Writer): $protobuf.Writer;

    /**
     * Decodes a KeyExchangeMessage message from the specified reader or buffer.
     * @param reader Reader or buffer to decode from
     * @param [length] Message length if known beforehand
     * @returns KeyExchangeMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): KeyExchangeMessage;

    /**
     * Decodes a KeyExchangeMessage message from the specified reader or buffer, length delimited.
     * @param reader Reader or buffer to decode from
     * @returns KeyExchangeMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): KeyExchangeMessage;

    /**
     * Verifies a KeyExchangeMessage message.
     * @param message Plain object to verify
     * @returns `null` if valid, otherwise the reason why it is not
     */
    public static verify(message: { [k: string]: any }): (string|null);

    /**
     * Creates a KeyExchangeMessage message from a plain object. Also converts values to their respective internal types.
     * @param object Plain object
     * @returns KeyExchangeMessage
     */
    public static fromObject(object: { [k: string]: any }): KeyExchangeMessage;

    /**
     * Creates a plain object from a KeyExchangeMessage message. Also converts values to other types if specified.
     * @param message KeyExchangeMessage
     * @param [options] Conversion options
     * @returns Plain object
     */
    public static toObject(message: KeyExchangeMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

    /**
     * Converts this KeyExchangeMessage to JSON.
     * @returns JSON object
     */
    public toJSON(): { [k: string]: any };

    /**
     * Gets the default type url for KeyExchangeMessage
     * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns The default type url
     */
    public static getTypeUrl(typeUrlPrefix?: string): string;
}
