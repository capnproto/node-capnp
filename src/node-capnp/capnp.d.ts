declare module Capnp {
  type Id = string;

  abstract class Schema<T> {
    typeId: Id;
  }

  function parse<T>(type: Schema<T>, buffer: Buffer): T;
}
export default Capnp;
