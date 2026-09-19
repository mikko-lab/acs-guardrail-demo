import { ExecutionCorrelationStore, CorrelationError } from "../src/execution-correlation";

describe("M-05: ExecutionCorrelationStore Tool Binding", () => {
  let store: ExecutionCorrelationStore;
  const sessA = "11111111-1111-4111-8111-111111111111";
  const reqR = "22222222-2222-4222-8222-222222222222";
  const sessB = "33333333-3333-4333-8333-333333333333";

  beforeEach(() => {
    store = new ExecutionCorrelationStore();
  });

  it("A. CORRECT TOOL", () => {
    store.registerExecution(sessA, reqR, "read_record");
    expect(() => store.validateAndConsume(sessA, reqR, "read_record")).not.toThrow();
  });

  it("B. WRONG TOOL", () => {
    store.registerExecution(sessA, reqR, "read_record");
    
    // Mismatch throws and does NOT consume
    expect(() => store.validateAndConsume(sessA, reqR, "update_record"))
      .toThrow(CorrelationError);
    
    // Original correct record is still available
    expect(() => store.validateAndConsume(sessA, reqR, "read_record")).not.toThrow();
  });

  it("C. UNKNOWN REQUEST", () => {
    expect(() => store.validateAndConsume(sessA, "unknown-req", "read_record"))
      .toThrow(CorrelationError);
  });

  it("D. CROSS SESSION", () => {
    store.registerExecution(sessA, reqR, "read_record");
    
    // Wrong session fails
    expect(() => store.validateAndConsume(sessB, reqR, "read_record"))
      .toThrow(CorrelationError);
      
    // Original correct session correlation remains usable
    expect(() => store.validateAndConsume(sessA, reqR, "read_record")).not.toThrow();
  });

  it("E. DUPLICATE RESULT", () => {
    store.registerExecution(sessA, reqR, "read_record");
    
    // First succeeds
    expect(() => store.validateAndConsume(sessA, reqR, "read_record")).not.toThrow();
    
    // Second fails (already consumed)
    expect(() => store.validateAndConsume(sessA, reqR, "read_record"))
      .toThrow(CorrelationError);
  });
});
