declare module Capnp {
  type Id = string;

  abstract class StructSchema<Builder, Reader> {
    // A schema for a struct type. The `Builder` parameter is what users of
    // the library specify in order to create a value; it may be missing fields,
    // which will be filled in with defaults. A `Reader` is what is is returned
    // when parsing a value, and is guaranteed to have all known fields set.

    typeId: Id;
  }

  abstract class InterfaceSchema<Server, Client> {
    // A schema for an interface type. Similarly to `StructSchema`, the `Server`
    // and `Client` parameters represent objects which may have missing
    // methods (for servers), and ones which do not (for clients, though calling
    // the method may still throw unimplemented).

    typeId: Id;
  }

  interface AnyServer {
    close?: () => void;
  }

  interface AnyClient {
    close(): void;
    closed: boolean;
    castAs<Server, Client>(schema: InterfaceSchema<Server, Client>): Client;
  }

  const Capability: {
    new<Server, Client>(server: Server, schema: InterfaceSchema<Server, Client>): Client;
  }

  abstract class Connection {
    restore<Server, Client>(exportName: string, type: InterfaceSchema<Server, Client>): Client;
    close(): void;
  }

  function parse<Builder, Reader>(type: StructSchema<Builder, Reader>, buffer: Buffer): Reader;
  function serialize<Builder, Reader>(type: StructSchema<Builder, Reader>, builder: Builder): Buffer;
  function connect(addr: string): Connection;
}
export default Capnp;
