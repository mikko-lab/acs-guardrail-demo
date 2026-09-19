export type ToolImplementation = (args: Record<string, unknown>) => Promise<any>;

export const executionCounters: Record<string, number> = {
  read_record: 0,
  update_record: 0,
  unknown_tool: 0,
};

export const resetCounters = () => {
  for (const key of Object.keys(executionCounters)) {
    executionCounters[key] = 0;
  }
};

export const tools: Record<string, ToolImplementation> = {
  read_record: async (args) => {
    executionCounters.read_record++;
    return { status: "success", data: "fake_record_data" };
  },
  update_record: async (args) => {
    executionCounters.update_record++;
    return { status: "success", modified: true };
  }
};

export const unknownToolMock: ToolImplementation = async (args) => {
  executionCounters.unknown_tool++;
  return { status: "error", message: "should never execute" };
};
