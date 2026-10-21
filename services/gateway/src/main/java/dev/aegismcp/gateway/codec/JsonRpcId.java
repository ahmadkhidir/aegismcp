package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.io.IOException;
import java.util.Objects;

/**
 * Representation of a JSON-RPC 2.0 message identifier.
 * Preserves exact type and value (string, number, or null) per JSON-RPC 2.0 and FEAT-001.
 * Anchors: FEAT-001, C-001.
 */
@JsonSerialize(using = JsonRpcId.Serializer.class)
@JsonDeserialize(using = JsonRpcId.Deserializer.class)
public sealed interface JsonRpcId permits JsonRpcId.StringId, JsonRpcId.NumberId, JsonRpcId.NullId {

    static JsonRpcId of(String value) {
        return value == null ? NullId.INSTANCE : new StringId(value);
    }

    static JsonRpcId of(long value) {
        return new NumberId(value);
    }

    static JsonRpcId of(Number value) {
        return value == null ? NullId.INSTANCE : new NumberId(value.longValue());
    }

    static JsonRpcId nullId() {
        return NullId.INSTANCE;
    }

    Object value();

    record StringId(String stringValue) implements JsonRpcId {
        public StringId {
            Objects.requireNonNull(stringValue, "stringValue must not be null");
        }

        @Override
        public Object value() {
            return stringValue;
        }

        @Override
        public String toString() {
            return stringValue;
        }
    }

    record NumberId(long numberValue) implements JsonRpcId {
        @Override
        public Object value() {
            return numberValue;
        }

        @Override
        public String toString() {
            return Long.toString(numberValue);
        }
    }

    enum NullId implements JsonRpcId {
        INSTANCE;

        @Override
        public Object value() {
            return null;
        }

        @Override
        public String toString() {
            return "null";
        }
    }

    class Serializer extends JsonSerializer<JsonRpcId> {
        @Override
        public void serialize(JsonRpcId id, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            if (id == null || id instanceof NullId) {
                gen.writeNull();
            } else if (id instanceof StringId s) {
                gen.writeString(s.stringValue());
            } else if (id instanceof NumberId n) {
                gen.writeNumber(n.numberValue());
            }
        }
    }

    class Deserializer extends JsonDeserializer<JsonRpcId> {
        @Override
        public JsonRpcId deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return switch (p.currentToken()) {
                case VALUE_STRING -> JsonRpcId.of(p.getText());
                case VALUE_NUMBER_INT -> JsonRpcId.of(p.getLongValue());
                case VALUE_NULL -> JsonRpcId.nullId();
                default -> throw ctxt.instantiationException(JsonRpcId.class,
                        "Invalid JSON-RPC id token type: " + p.currentToken());
            };
        }
    }
}
