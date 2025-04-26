/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
import * as $protobuf from "protobufjs/minimal";

// Common aliases
const $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const SignalMessage = $root.SignalMessage = (() => {

    /**
     * Properties of a SignalMessage.
     * @exports ISignalMessage
     * @interface ISignalMessage
     * @property {Uint8Array|null} [ratchetKey] SignalMessage ratchetKey
     * @property {number|null} [counter] SignalMessage counter
     * @property {number|null} [previousCounter] SignalMessage previousCounter
     * @property {Uint8Array|null} [ciphertext] SignalMessage ciphertext
     */

    /**
     * Constructs a new SignalMessage.
     * @exports SignalMessage
     * @classdesc Represents a SignalMessage.
     * @implements ISignalMessage
     * @constructor
     * @param {ISignalMessage=} [properties] Properties to set
     */
    function SignalMessage(properties) {
        if (properties)
            for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                if (properties[keys[i]] != null)
                    this[keys[i]] = properties[keys[i]];
    }

    /**
     * SignalMessage ratchetKey.
     * @member {Uint8Array} ratchetKey
     * @memberof SignalMessage
     * @instance
     */
    SignalMessage.prototype.ratchetKey = $util.newBuffer([]);

    /**
     * SignalMessage counter.
     * @member {number} counter
     * @memberof SignalMessage
     * @instance
     */
    SignalMessage.prototype.counter = 0;

    /**
     * SignalMessage previousCounter.
     * @member {number} previousCounter
     * @memberof SignalMessage
     * @instance
     */
    SignalMessage.prototype.previousCounter = 0;

    /**
     * SignalMessage ciphertext.
     * @member {Uint8Array} ciphertext
     * @memberof SignalMessage
     * @instance
     */
    SignalMessage.prototype.ciphertext = $util.newBuffer([]);

    /**
     * Creates a new SignalMessage instance using the specified properties.
     * @function create
     * @memberof SignalMessage
     * @static
     * @param {ISignalMessage=} [properties] Properties to set
     * @returns {SignalMessage} SignalMessage instance
     */
    SignalMessage.create = function create(properties) {
        return new SignalMessage(properties);
    };

    /**
     * Encodes the specified SignalMessage message. Does not implicitly {@link SignalMessage.verify|verify} messages.
     * @function encode
     * @memberof SignalMessage
     * @static
     * @param {ISignalMessage} message SignalMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    SignalMessage.encode = function encode(message, writer) {
        if (!writer)
            writer = $Writer.create();
        if (message.ratchetKey != null && Object.hasOwnProperty.call(message, "ratchetKey"))
            writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.ratchetKey);
        if (message.counter != null && Object.hasOwnProperty.call(message, "counter"))
            writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.counter);
        if (message.previousCounter != null && Object.hasOwnProperty.call(message, "previousCounter"))
            writer.uint32(/* id 3, wireType 0 =*/24).uint32(message.previousCounter);
        if (message.ciphertext != null && Object.hasOwnProperty.call(message, "ciphertext"))
            writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.ciphertext);
        return writer;
    };

    /**
     * Encodes the specified SignalMessage message, length delimited. Does not implicitly {@link SignalMessage.verify|verify} messages.
     * @function encodeDelimited
     * @memberof SignalMessage
     * @static
     * @param {ISignalMessage} message SignalMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    SignalMessage.encodeDelimited = function encodeDelimited(message, writer) {
        return this.encode(message, writer).ldelim();
    };

    /**
     * Decodes a SignalMessage message from the specified reader or buffer.
     * @function decode
     * @memberof SignalMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @param {number} [length] Message length if known beforehand
     * @returns {SignalMessage} SignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    SignalMessage.decode = function decode(reader, length, error) {
        if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
        let end = length === undefined ? reader.len : reader.pos + length, message = new $root.SignalMessage();
        while (reader.pos < end) {
            let tag = reader.uint32();
            if (tag === error)
                break;
            switch (tag >>> 3) {
            case 1: {
                    message.ratchetKey = reader.bytes();
                    break;
                }
            case 2: {
                    message.counter = reader.uint32();
                    break;
                }
            case 3: {
                    message.previousCounter = reader.uint32();
                    break;
                }
            case 4: {
                    message.ciphertext = reader.bytes();
                    break;
                }
            default:
                reader.skipType(tag & 7);
                break;
            }
        }
        return message;
    };

    /**
     * Decodes a SignalMessage message from the specified reader or buffer, length delimited.
     * @function decodeDelimited
     * @memberof SignalMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @returns {SignalMessage} SignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    SignalMessage.decodeDelimited = function decodeDelimited(reader) {
        if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
        return this.decode(reader, reader.uint32());
    };

    /**
     * Verifies a SignalMessage message.
     * @function verify
     * @memberof SignalMessage
     * @static
     * @param {Object.<string,*>} message Plain object to verify
     * @returns {string|null} `null` if valid, otherwise the reason why it is not
     */
    SignalMessage.verify = function verify(message) {
        if (typeof message !== "object" || message === null)
            return "object expected";
        if (message.ratchetKey != null && message.hasOwnProperty("ratchetKey"))
            if (!(message.ratchetKey && typeof message.ratchetKey.length === "number" || $util.isString(message.ratchetKey)))
                return "ratchetKey: buffer expected";
        if (message.counter != null && message.hasOwnProperty("counter"))
            if (!$util.isInteger(message.counter))
                return "counter: integer expected";
        if (message.previousCounter != null && message.hasOwnProperty("previousCounter"))
            if (!$util.isInteger(message.previousCounter))
                return "previousCounter: integer expected";
        if (message.ciphertext != null && message.hasOwnProperty("ciphertext"))
            if (!(message.ciphertext && typeof message.ciphertext.length === "number" || $util.isString(message.ciphertext)))
                return "ciphertext: buffer expected";
        return null;
    };

    /**
     * Creates a SignalMessage message from a plain object. Also converts values to their respective internal types.
     * @function fromObject
     * @memberof SignalMessage
     * @static
     * @param {Object.<string,*>} object Plain object
     * @returns {SignalMessage} SignalMessage
     */
    SignalMessage.fromObject = function fromObject(object) {
        if (object instanceof $root.SignalMessage)
            return object;
        let message = new $root.SignalMessage();
        if (object.ratchetKey != null)
            if (typeof object.ratchetKey === "string")
                $util.base64.decode(object.ratchetKey, message.ratchetKey = $util.newBuffer($util.base64.length(object.ratchetKey)), 0);
            else if (object.ratchetKey.length >= 0)
                message.ratchetKey = object.ratchetKey;
        if (object.counter != null)
            message.counter = object.counter >>> 0;
        if (object.previousCounter != null)
            message.previousCounter = object.previousCounter >>> 0;
        if (object.ciphertext != null)
            if (typeof object.ciphertext === "string")
                $util.base64.decode(object.ciphertext, message.ciphertext = $util.newBuffer($util.base64.length(object.ciphertext)), 0);
            else if (object.ciphertext.length >= 0)
                message.ciphertext = object.ciphertext;
        return message;
    };

    /**
     * Creates a plain object from a SignalMessage message. Also converts values to other types if specified.
     * @function toObject
     * @memberof SignalMessage
     * @static
     * @param {SignalMessage} message SignalMessage
     * @param {$protobuf.IConversionOptions} [options] Conversion options
     * @returns {Object.<string,*>} Plain object
     */
    SignalMessage.toObject = function toObject(message, options) {
        if (!options)
            options = {};
        let object = {};
        if (options.defaults) {
            if (options.bytes === String)
                object.ratchetKey = "";
            else {
                object.ratchetKey = [];
                if (options.bytes !== Array)
                    object.ratchetKey = $util.newBuffer(object.ratchetKey);
            }
            object.counter = 0;
            object.previousCounter = 0;
            if (options.bytes === String)
                object.ciphertext = "";
            else {
                object.ciphertext = [];
                if (options.bytes !== Array)
                    object.ciphertext = $util.newBuffer(object.ciphertext);
            }
        }
        if (message.ratchetKey != null && message.hasOwnProperty("ratchetKey"))
            object.ratchetKey = options.bytes === String ? $util.base64.encode(message.ratchetKey, 0, message.ratchetKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.ratchetKey) : message.ratchetKey;
        if (message.counter != null && message.hasOwnProperty("counter"))
            object.counter = message.counter;
        if (message.previousCounter != null && message.hasOwnProperty("previousCounter"))
            object.previousCounter = message.previousCounter;
        if (message.ciphertext != null && message.hasOwnProperty("ciphertext"))
            object.ciphertext = options.bytes === String ? $util.base64.encode(message.ciphertext, 0, message.ciphertext.length) : options.bytes === Array ? Array.prototype.slice.call(message.ciphertext) : message.ciphertext;
        return object;
    };

    /**
     * Converts this SignalMessage to JSON.
     * @function toJSON
     * @memberof SignalMessage
     * @instance
     * @returns {Object.<string,*>} JSON object
     */
    SignalMessage.prototype.toJSON = function toJSON() {
        return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
    };

    /**
     * Gets the default type url for SignalMessage
     * @function getTypeUrl
     * @memberof SignalMessage
     * @static
     * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns {string} The default type url
     */
    SignalMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
        if (typeUrlPrefix === undefined) {
            typeUrlPrefix = "type.googleapis.com";
        }
        return typeUrlPrefix + "/SignalMessage";
    };

    return SignalMessage;
})();

export const PreKeySignalMessage = $root.PreKeySignalMessage = (() => {

    /**
     * Properties of a PreKeySignalMessage.
     * @exports IPreKeySignalMessage
     * @interface IPreKeySignalMessage
     * @property {number|null} [registrationId] PreKeySignalMessage registrationId
     * @property {number|null} [preKeyId] PreKeySignalMessage preKeyId
     * @property {number|null} [signedPreKeyId] PreKeySignalMessage signedPreKeyId
     * @property {Uint8Array|null} [baseKey] PreKeySignalMessage baseKey
     * @property {Uint8Array|null} [identityKey] PreKeySignalMessage identityKey
     * @property {Uint8Array|null} [message] PreKeySignalMessage message
     */

    /**
     * Constructs a new PreKeySignalMessage.
     * @exports PreKeySignalMessage
     * @classdesc Represents a PreKeySignalMessage.
     * @implements IPreKeySignalMessage
     * @constructor
     * @param {IPreKeySignalMessage=} [properties] Properties to set
     */
    function PreKeySignalMessage(properties) {
        if (properties)
            for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                if (properties[keys[i]] != null)
                    this[keys[i]] = properties[keys[i]];
    }

    /**
     * PreKeySignalMessage registrationId.
     * @member {number} registrationId
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.registrationId = 0;

    /**
     * PreKeySignalMessage preKeyId.
     * @member {number} preKeyId
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.preKeyId = 0;

    /**
     * PreKeySignalMessage signedPreKeyId.
     * @member {number} signedPreKeyId
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.signedPreKeyId = 0;

    /**
     * PreKeySignalMessage baseKey.
     * @member {Uint8Array} baseKey
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.baseKey = $util.newBuffer([]);

    /**
     * PreKeySignalMessage identityKey.
     * @member {Uint8Array} identityKey
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.identityKey = $util.newBuffer([]);

    /**
     * PreKeySignalMessage message.
     * @member {Uint8Array} message
     * @memberof PreKeySignalMessage
     * @instance
     */
    PreKeySignalMessage.prototype.message = $util.newBuffer([]);

    /**
     * Creates a new PreKeySignalMessage instance using the specified properties.
     * @function create
     * @memberof PreKeySignalMessage
     * @static
     * @param {IPreKeySignalMessage=} [properties] Properties to set
     * @returns {PreKeySignalMessage} PreKeySignalMessage instance
     */
    PreKeySignalMessage.create = function create(properties) {
        return new PreKeySignalMessage(properties);
    };

    /**
     * Encodes the specified PreKeySignalMessage message. Does not implicitly {@link PreKeySignalMessage.verify|verify} messages.
     * @function encode
     * @memberof PreKeySignalMessage
     * @static
     * @param {IPreKeySignalMessage} message PreKeySignalMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    PreKeySignalMessage.encode = function encode(message, writer) {
        if (!writer)
            writer = $Writer.create();
        if (message.preKeyId != null && Object.hasOwnProperty.call(message, "preKeyId"))
            writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.preKeyId);
        if (message.baseKey != null && Object.hasOwnProperty.call(message, "baseKey"))
            writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.baseKey);
        if (message.identityKey != null && Object.hasOwnProperty.call(message, "identityKey"))
            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.identityKey);
        if (message.message != null && Object.hasOwnProperty.call(message, "message"))
            writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.message);
        if (message.registrationId != null && Object.hasOwnProperty.call(message, "registrationId"))
            writer.uint32(/* id 5, wireType 0 =*/40).uint32(message.registrationId);
        if (message.signedPreKeyId != null && Object.hasOwnProperty.call(message, "signedPreKeyId"))
            writer.uint32(/* id 6, wireType 0 =*/48).uint32(message.signedPreKeyId);
        return writer;
    };

    /**
     * Encodes the specified PreKeySignalMessage message, length delimited. Does not implicitly {@link PreKeySignalMessage.verify|verify} messages.
     * @function encodeDelimited
     * @memberof PreKeySignalMessage
     * @static
     * @param {IPreKeySignalMessage} message PreKeySignalMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    PreKeySignalMessage.encodeDelimited = function encodeDelimited(message, writer) {
        return this.encode(message, writer).ldelim();
    };

    /**
     * Decodes a PreKeySignalMessage message from the specified reader or buffer.
     * @function decode
     * @memberof PreKeySignalMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @param {number} [length] Message length if known beforehand
     * @returns {PreKeySignalMessage} PreKeySignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    PreKeySignalMessage.decode = function decode(reader, length, error) {
        if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
        let end = length === undefined ? reader.len : reader.pos + length, message = new $root.PreKeySignalMessage();
        while (reader.pos < end) {
            let tag = reader.uint32();
            if (tag === error)
                break;
            switch (tag >>> 3) {
            case 5: {
                    message.registrationId = reader.uint32();
                    break;
                }
            case 1: {
                    message.preKeyId = reader.uint32();
                    break;
                }
            case 6: {
                    message.signedPreKeyId = reader.uint32();
                    break;
                }
            case 2: {
                    message.baseKey = reader.bytes();
                    break;
                }
            case 3: {
                    message.identityKey = reader.bytes();
                    break;
                }
            case 4: {
                    message.message = reader.bytes();
                    break;
                }
            default:
                reader.skipType(tag & 7);
                break;
            }
        }
        return message;
    };

    /**
     * Decodes a PreKeySignalMessage message from the specified reader or buffer, length delimited.
     * @function decodeDelimited
     * @memberof PreKeySignalMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @returns {PreKeySignalMessage} PreKeySignalMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    PreKeySignalMessage.decodeDelimited = function decodeDelimited(reader) {
        if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
        return this.decode(reader, reader.uint32());
    };

    /**
     * Verifies a PreKeySignalMessage message.
     * @function verify
     * @memberof PreKeySignalMessage
     * @static
     * @param {Object.<string,*>} message Plain object to verify
     * @returns {string|null} `null` if valid, otherwise the reason why it is not
     */
    PreKeySignalMessage.verify = function verify(message) {
        if (typeof message !== "object" || message === null)
            return "object expected";
        if (message.registrationId != null && message.hasOwnProperty("registrationId"))
            if (!$util.isInteger(message.registrationId))
                return "registrationId: integer expected";
        if (message.preKeyId != null && message.hasOwnProperty("preKeyId"))
            if (!$util.isInteger(message.preKeyId))
                return "preKeyId: integer expected";
        if (message.signedPreKeyId != null && message.hasOwnProperty("signedPreKeyId"))
            if (!$util.isInteger(message.signedPreKeyId))
                return "signedPreKeyId: integer expected";
        if (message.baseKey != null && message.hasOwnProperty("baseKey"))
            if (!(message.baseKey && typeof message.baseKey.length === "number" || $util.isString(message.baseKey)))
                return "baseKey: buffer expected";
        if (message.identityKey != null && message.hasOwnProperty("identityKey"))
            if (!(message.identityKey && typeof message.identityKey.length === "number" || $util.isString(message.identityKey)))
                return "identityKey: buffer expected";
        if (message.message != null && message.hasOwnProperty("message"))
            if (!(message.message && typeof message.message.length === "number" || $util.isString(message.message)))
                return "message: buffer expected";
        return null;
    };

    /**
     * Creates a PreKeySignalMessage message from a plain object. Also converts values to their respective internal types.
     * @function fromObject
     * @memberof PreKeySignalMessage
     * @static
     * @param {Object.<string,*>} object Plain object
     * @returns {PreKeySignalMessage} PreKeySignalMessage
     */
    PreKeySignalMessage.fromObject = function fromObject(object) {
        if (object instanceof $root.PreKeySignalMessage)
            return object;
        let message = new $root.PreKeySignalMessage();
        if (object.registrationId != null)
            message.registrationId = object.registrationId >>> 0;
        if (object.preKeyId != null)
            message.preKeyId = object.preKeyId >>> 0;
        if (object.signedPreKeyId != null)
            message.signedPreKeyId = object.signedPreKeyId >>> 0;
        if (object.baseKey != null)
            if (typeof object.baseKey === "string")
                $util.base64.decode(object.baseKey, message.baseKey = $util.newBuffer($util.base64.length(object.baseKey)), 0);
            else if (object.baseKey.length >= 0)
                message.baseKey = object.baseKey;
        if (object.identityKey != null)
            if (typeof object.identityKey === "string")
                $util.base64.decode(object.identityKey, message.identityKey = $util.newBuffer($util.base64.length(object.identityKey)), 0);
            else if (object.identityKey.length >= 0)
                message.identityKey = object.identityKey;
        if (object.message != null)
            if (typeof object.message === "string")
                $util.base64.decode(object.message, message.message = $util.newBuffer($util.base64.length(object.message)), 0);
            else if (object.message.length >= 0)
                message.message = object.message;
        return message;
    };

    /**
     * Creates a plain object from a PreKeySignalMessage message. Also converts values to other types if specified.
     * @function toObject
     * @memberof PreKeySignalMessage
     * @static
     * @param {PreKeySignalMessage} message PreKeySignalMessage
     * @param {$protobuf.IConversionOptions} [options] Conversion options
     * @returns {Object.<string,*>} Plain object
     */
    PreKeySignalMessage.toObject = function toObject(message, options) {
        if (!options)
            options = {};
        let object = {};
        if (options.defaults) {
            object.preKeyId = 0;
            if (options.bytes === String)
                object.baseKey = "";
            else {
                object.baseKey = [];
                if (options.bytes !== Array)
                    object.baseKey = $util.newBuffer(object.baseKey);
            }
            if (options.bytes === String)
                object.identityKey = "";
            else {
                object.identityKey = [];
                if (options.bytes !== Array)
                    object.identityKey = $util.newBuffer(object.identityKey);
            }
            if (options.bytes === String)
                object.message = "";
            else {
                object.message = [];
                if (options.bytes !== Array)
                    object.message = $util.newBuffer(object.message);
            }
            object.registrationId = 0;
            object.signedPreKeyId = 0;
        }
        if (message.preKeyId != null && message.hasOwnProperty("preKeyId"))
            object.preKeyId = message.preKeyId;
        if (message.baseKey != null && message.hasOwnProperty("baseKey"))
            object.baseKey = options.bytes === String ? $util.base64.encode(message.baseKey, 0, message.baseKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKey) : message.baseKey;
        if (message.identityKey != null && message.hasOwnProperty("identityKey"))
            object.identityKey = options.bytes === String ? $util.base64.encode(message.identityKey, 0, message.identityKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.identityKey) : message.identityKey;
        if (message.message != null && message.hasOwnProperty("message"))
            object.message = options.bytes === String ? $util.base64.encode(message.message, 0, message.message.length) : options.bytes === Array ? Array.prototype.slice.call(message.message) : message.message;
        if (message.registrationId != null && message.hasOwnProperty("registrationId"))
            object.registrationId = message.registrationId;
        if (message.signedPreKeyId != null && message.hasOwnProperty("signedPreKeyId"))
            object.signedPreKeyId = message.signedPreKeyId;
        return object;
    };

    /**
     * Converts this PreKeySignalMessage to JSON.
     * @function toJSON
     * @memberof PreKeySignalMessage
     * @instance
     * @returns {Object.<string,*>} JSON object
     */
    PreKeySignalMessage.prototype.toJSON = function toJSON() {
        return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
    };

    /**
     * Gets the default type url for PreKeySignalMessage
     * @function getTypeUrl
     * @memberof PreKeySignalMessage
     * @static
     * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns {string} The default type url
     */
    PreKeySignalMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
        if (typeUrlPrefix === undefined) {
            typeUrlPrefix = "type.googleapis.com";
        }
        return typeUrlPrefix + "/PreKeySignalMessage";
    };

    return PreKeySignalMessage;
})();

export const KeyExchangeMessage = $root.KeyExchangeMessage = (() => {

    /**
     * Properties of a KeyExchangeMessage.
     * @exports IKeyExchangeMessage
     * @interface IKeyExchangeMessage
     * @property {number|null} [id] KeyExchangeMessage id
     * @property {Uint8Array|null} [baseKey] KeyExchangeMessage baseKey
     * @property {Uint8Array|null} [ratchetKey] KeyExchangeMessage ratchetKey
     * @property {Uint8Array|null} [identityKey] KeyExchangeMessage identityKey
     * @property {Uint8Array|null} [baseKeySignature] KeyExchangeMessage baseKeySignature
     */

    /**
     * Constructs a new KeyExchangeMessage.
     * @exports KeyExchangeMessage
     * @classdesc Represents a KeyExchangeMessage.
     * @implements IKeyExchangeMessage
     * @constructor
     * @param {IKeyExchangeMessage=} [properties] Properties to set
     */
    function KeyExchangeMessage(properties) {
        if (properties)
            for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                if (properties[keys[i]] != null)
                    this[keys[i]] = properties[keys[i]];
    }

    /**
     * KeyExchangeMessage id.
     * @member {number} id
     * @memberof KeyExchangeMessage
     * @instance
     */
    KeyExchangeMessage.prototype.id = 0;

    /**
     * KeyExchangeMessage baseKey.
     * @member {Uint8Array} baseKey
     * @memberof KeyExchangeMessage
     * @instance
     */
    KeyExchangeMessage.prototype.baseKey = $util.newBuffer([]);

    /**
     * KeyExchangeMessage ratchetKey.
     * @member {Uint8Array} ratchetKey
     * @memberof KeyExchangeMessage
     * @instance
     */
    KeyExchangeMessage.prototype.ratchetKey = $util.newBuffer([]);

    /**
     * KeyExchangeMessage identityKey.
     * @member {Uint8Array} identityKey
     * @memberof KeyExchangeMessage
     * @instance
     */
    KeyExchangeMessage.prototype.identityKey = $util.newBuffer([]);

    /**
     * KeyExchangeMessage baseKeySignature.
     * @member {Uint8Array} baseKeySignature
     * @memberof KeyExchangeMessage
     * @instance
     */
    KeyExchangeMessage.prototype.baseKeySignature = $util.newBuffer([]);

    /**
     * Creates a new KeyExchangeMessage instance using the specified properties.
     * @function create
     * @memberof KeyExchangeMessage
     * @static
     * @param {IKeyExchangeMessage=} [properties] Properties to set
     * @returns {KeyExchangeMessage} KeyExchangeMessage instance
     */
    KeyExchangeMessage.create = function create(properties) {
        return new KeyExchangeMessage(properties);
    };

    /**
     * Encodes the specified KeyExchangeMessage message. Does not implicitly {@link KeyExchangeMessage.verify|verify} messages.
     * @function encode
     * @memberof KeyExchangeMessage
     * @static
     * @param {IKeyExchangeMessage} message KeyExchangeMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    KeyExchangeMessage.encode = function encode(message, writer) {
        if (!writer)
            writer = $Writer.create();
        if (message.id != null && Object.hasOwnProperty.call(message, "id"))
            writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.id);
        if (message.baseKey != null && Object.hasOwnProperty.call(message, "baseKey"))
            writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.baseKey);
        if (message.ratchetKey != null && Object.hasOwnProperty.call(message, "ratchetKey"))
            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.ratchetKey);
        if (message.identityKey != null && Object.hasOwnProperty.call(message, "identityKey"))
            writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.identityKey);
        if (message.baseKeySignature != null && Object.hasOwnProperty.call(message, "baseKeySignature"))
            writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.baseKeySignature);
        return writer;
    };

    /**
     * Encodes the specified KeyExchangeMessage message, length delimited. Does not implicitly {@link KeyExchangeMessage.verify|verify} messages.
     * @function encodeDelimited
     * @memberof KeyExchangeMessage
     * @static
     * @param {IKeyExchangeMessage} message KeyExchangeMessage message or plain object to encode
     * @param {$protobuf.Writer} [writer] Writer to encode to
     * @returns {$protobuf.Writer} Writer
     */
    KeyExchangeMessage.encodeDelimited = function encodeDelimited(message, writer) {
        return this.encode(message, writer).ldelim();
    };

    /**
     * Decodes a KeyExchangeMessage message from the specified reader or buffer.
     * @function decode
     * @memberof KeyExchangeMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @param {number} [length] Message length if known beforehand
     * @returns {KeyExchangeMessage} KeyExchangeMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    KeyExchangeMessage.decode = function decode(reader, length, error) {
        if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
        let end = length === undefined ? reader.len : reader.pos + length, message = new $root.KeyExchangeMessage();
        while (reader.pos < end) {
            let tag = reader.uint32();
            if (tag === error)
                break;
            switch (tag >>> 3) {
            case 1: {
                    message.id = reader.uint32();
                    break;
                }
            case 2: {
                    message.baseKey = reader.bytes();
                    break;
                }
            case 3: {
                    message.ratchetKey = reader.bytes();
                    break;
                }
            case 4: {
                    message.identityKey = reader.bytes();
                    break;
                }
            case 5: {
                    message.baseKeySignature = reader.bytes();
                    break;
                }
            default:
                reader.skipType(tag & 7);
                break;
            }
        }
        return message;
    };

    /**
     * Decodes a KeyExchangeMessage message from the specified reader or buffer, length delimited.
     * @function decodeDelimited
     * @memberof KeyExchangeMessage
     * @static
     * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
     * @returns {KeyExchangeMessage} KeyExchangeMessage
     * @throws {Error} If the payload is not a reader or valid buffer
     * @throws {$protobuf.util.ProtocolError} If required fields are missing
     */
    KeyExchangeMessage.decodeDelimited = function decodeDelimited(reader) {
        if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
        return this.decode(reader, reader.uint32());
    };

    /**
     * Verifies a KeyExchangeMessage message.
     * @function verify
     * @memberof KeyExchangeMessage
     * @static
     * @param {Object.<string,*>} message Plain object to verify
     * @returns {string|null} `null` if valid, otherwise the reason why it is not
     */
    KeyExchangeMessage.verify = function verify(message) {
        if (typeof message !== "object" || message === null)
            return "object expected";
        if (message.id != null && message.hasOwnProperty("id"))
            if (!$util.isInteger(message.id))
                return "id: integer expected";
        if (message.baseKey != null && message.hasOwnProperty("baseKey"))
            if (!(message.baseKey && typeof message.baseKey.length === "number" || $util.isString(message.baseKey)))
                return "baseKey: buffer expected";
        if (message.ratchetKey != null && message.hasOwnProperty("ratchetKey"))
            if (!(message.ratchetKey && typeof message.ratchetKey.length === "number" || $util.isString(message.ratchetKey)))
                return "ratchetKey: buffer expected";
        if (message.identityKey != null && message.hasOwnProperty("identityKey"))
            if (!(message.identityKey && typeof message.identityKey.length === "number" || $util.isString(message.identityKey)))
                return "identityKey: buffer expected";
        if (message.baseKeySignature != null && message.hasOwnProperty("baseKeySignature"))
            if (!(message.baseKeySignature && typeof message.baseKeySignature.length === "number" || $util.isString(message.baseKeySignature)))
                return "baseKeySignature: buffer expected";
        return null;
    };

    /**
     * Creates a KeyExchangeMessage message from a plain object. Also converts values to their respective internal types.
     * @function fromObject
     * @memberof KeyExchangeMessage
     * @static
     * @param {Object.<string,*>} object Plain object
     * @returns {KeyExchangeMessage} KeyExchangeMessage
     */
    KeyExchangeMessage.fromObject = function fromObject(object) {
        if (object instanceof $root.KeyExchangeMessage)
            return object;
        let message = new $root.KeyExchangeMessage();
        if (object.id != null)
            message.id = object.id >>> 0;
        if (object.baseKey != null)
            if (typeof object.baseKey === "string")
                $util.base64.decode(object.baseKey, message.baseKey = $util.newBuffer($util.base64.length(object.baseKey)), 0);
            else if (object.baseKey.length >= 0)
                message.baseKey = object.baseKey;
        if (object.ratchetKey != null)
            if (typeof object.ratchetKey === "string")
                $util.base64.decode(object.ratchetKey, message.ratchetKey = $util.newBuffer($util.base64.length(object.ratchetKey)), 0);
            else if (object.ratchetKey.length >= 0)
                message.ratchetKey = object.ratchetKey;
        if (object.identityKey != null)
            if (typeof object.identityKey === "string")
                $util.base64.decode(object.identityKey, message.identityKey = $util.newBuffer($util.base64.length(object.identityKey)), 0);
            else if (object.identityKey.length >= 0)
                message.identityKey = object.identityKey;
        if (object.baseKeySignature != null)
            if (typeof object.baseKeySignature === "string")
                $util.base64.decode(object.baseKeySignature, message.baseKeySignature = $util.newBuffer($util.base64.length(object.baseKeySignature)), 0);
            else if (object.baseKeySignature.length >= 0)
                message.baseKeySignature = object.baseKeySignature;
        return message;
    };

    /**
     * Creates a plain object from a KeyExchangeMessage message. Also converts values to other types if specified.
     * @function toObject
     * @memberof KeyExchangeMessage
     * @static
     * @param {KeyExchangeMessage} message KeyExchangeMessage
     * @param {$protobuf.IConversionOptions} [options] Conversion options
     * @returns {Object.<string,*>} Plain object
     */
    KeyExchangeMessage.toObject = function toObject(message, options) {
        if (!options)
            options = {};
        let object = {};
        if (options.defaults) {
            object.id = 0;
            if (options.bytes === String)
                object.baseKey = "";
            else {
                object.baseKey = [];
                if (options.bytes !== Array)
                    object.baseKey = $util.newBuffer(object.baseKey);
            }
            if (options.bytes === String)
                object.ratchetKey = "";
            else {
                object.ratchetKey = [];
                if (options.bytes !== Array)
                    object.ratchetKey = $util.newBuffer(object.ratchetKey);
            }
            if (options.bytes === String)
                object.identityKey = "";
            else {
                object.identityKey = [];
                if (options.bytes !== Array)
                    object.identityKey = $util.newBuffer(object.identityKey);
            }
            if (options.bytes === String)
                object.baseKeySignature = "";
            else {
                object.baseKeySignature = [];
                if (options.bytes !== Array)
                    object.baseKeySignature = $util.newBuffer(object.baseKeySignature);
            }
        }
        if (message.id != null && message.hasOwnProperty("id"))
            object.id = message.id;
        if (message.baseKey != null && message.hasOwnProperty("baseKey"))
            object.baseKey = options.bytes === String ? $util.base64.encode(message.baseKey, 0, message.baseKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKey) : message.baseKey;
        if (message.ratchetKey != null && message.hasOwnProperty("ratchetKey"))
            object.ratchetKey = options.bytes === String ? $util.base64.encode(message.ratchetKey, 0, message.ratchetKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.ratchetKey) : message.ratchetKey;
        if (message.identityKey != null && message.hasOwnProperty("identityKey"))
            object.identityKey = options.bytes === String ? $util.base64.encode(message.identityKey, 0, message.identityKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.identityKey) : message.identityKey;
        if (message.baseKeySignature != null && message.hasOwnProperty("baseKeySignature"))
            object.baseKeySignature = options.bytes === String ? $util.base64.encode(message.baseKeySignature, 0, message.baseKeySignature.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKeySignature) : message.baseKeySignature;
        return object;
    };

    /**
     * Converts this KeyExchangeMessage to JSON.
     * @function toJSON
     * @memberof KeyExchangeMessage
     * @instance
     * @returns {Object.<string,*>} JSON object
     */
    KeyExchangeMessage.prototype.toJSON = function toJSON() {
        return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
    };

    /**
     * Gets the default type url for KeyExchangeMessage
     * @function getTypeUrl
     * @memberof KeyExchangeMessage
     * @static
     * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
     * @returns {string} The default type url
     */
    KeyExchangeMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
        if (typeUrlPrefix === undefined) {
            typeUrlPrefix = "type.googleapis.com";
        }
        return typeUrlPrefix + "/KeyExchangeMessage";
    };

    return KeyExchangeMessage;
})();

export { $root as default };
