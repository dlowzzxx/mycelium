export class MyceliumProtocolError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  readonly effectId?: string;
  readonly retryClassification: string;
  readonly stateMayHaveChanged: boolean;
  readonly providerEffectMayHaveHappened: boolean;
  readonly details?: unknown;

  constructor(message: string, fields: {
    code: string; httpStatus: number; effectId?: string;
    retryClassification?: string; stateMayHaveChanged?: boolean;
    providerEffectMayHaveHappened?: boolean; details?: unknown;
  }) {
    super(message);
    this.name = "MyceliumProtocolError";
    this.code = fields.code;
    this.httpStatus = fields.httpStatus;
    this.effectId = fields.effectId;
    this.retryClassification = fields.retryClassification ?? "caller_action_required";
    this.stateMayHaveChanged = fields.stateMayHaveChanged ?? true;
    this.providerEffectMayHaveHappened = fields.providerEffectMayHaveHappened ?? true;
    this.details = fields.details;
  }
}

export class MyceliumTransportError extends Error {
  readonly stateMayHaveChanged = true as const;
  readonly providerEffectMayHaveHappened = true as const;
  readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MyceliumTransportError";
    this.cause = cause;
  }
}

export class MyceliumLocalValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MyceliumLocalValidationError";
  }
}
