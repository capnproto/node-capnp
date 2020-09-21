declare module Capnp {
  type Id = string;

  abstract class StructSchema<Builder, Reader> {
    typeId: Id;
  }

  abstract class InterfaceSchema<Server, Client> {
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
  function serialize<Builder, Reader>(type: StructSchema<Builder, Reader>, reader: Reader): Buffer;
  function connect(addr: string): Connection;
}
export default Capnp;
