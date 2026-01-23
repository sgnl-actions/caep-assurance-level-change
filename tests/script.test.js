import { jest } from '@jest/globals';

// Mock @sgnl-ai/set-transmitter module
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn().mockResolvedValue({
    status: 'success',
    statusCode: 200,
    body: '{"success":true}',
    retryable: false
  })
}));

// Mock @sgnl-actions/utils module
jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  signSET: jest.fn().mockResolvedValue('mock.jwt.token'),
  getBaseURL: jest.fn((params, context) => params.address || context.environment?.ADDRESS),
  getAuthorizationHeader: jest.fn().mockResolvedValue('Bearer test-token')
}));

// Import after mocking
const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { signSET, getBaseURL, getAuthorizationHeader } = await import('@sgnl-actions/utils');
const script = (await import('../src/script.mjs')).default;

describe('CAEP Assurance Level Change Transmitter', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'https://receiver.example.com/events'
    },
    secrets: {
      BEARER_AUTH_TOKEN: 'Bearer test-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    signSET.mockClear();
    signSET.mockResolvedValue('mock.jwt.token');
    getBaseURL.mockClear();
    getBaseURL.mockImplementation((params, context) => params.address || context.environment?.ADDRESS);
    getAuthorizationHeader.mockClear();
    getAuthorizationHeader.mockResolvedValue('Bearer test-token');
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '{"success":true}',
      retryable: false
    });
  });

  describe('invoke', () => {
    const validParams = {
      audience: 'https://example.com',
      subject: '{"format":"account","uri":"acct:user@service.example.com"}',
      namespace: 'NIST-AAL',
      current_level: 'nist-aal2'
    };

    test('should successfully transmit an assurance level change event', async () => {
      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"success":true}',
        retryable: false
      });

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        {
          aud: 'https://example.com',
          sub_id: {
            format: 'account',
            uri: 'acct:user@service.example.com'
          },
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change': expect.objectContaining({
              event_timestamp: expect.any(Number),
              namespace: 'NIST-AAL',
              current_level: 'nist-aal2'
            })
          }
        }
      );
    });

    test('should include optional fields when provided', async () => {
      const params = {
        ...validParams,
        previous_level: 'nist-aal1',
        change_direction: 'increase',
        initiating_entity: 'policy',
        reason_admin: 'MFA requirement triggered',
        reason_user: 'Additional authentication required'
      };

      await script.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change': expect.objectContaining({
              event_timestamp: expect.any(Number),
              namespace: 'NIST-AAL',
              current_level: 'nist-aal2',
              previous_level: 'nist-aal1',
              change_direction: 'increase',
              initiating_entity: 'policy',
              reason_admin: 'MFA requirement triggered',
              reason_user: 'Additional authentication required'
            })
          }
        })
      );
    });

    test('should parse i18n reason_admin JSON format', async () => {
      const params = {
        ...validParams,
        reason_admin: '{"en":"Policy violation","es":"Violación de política"}'
      };

      await script.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change': expect.objectContaining({
              reason_admin: {
                en: 'Policy violation',
                es: 'Violación de política'
              }
            })
          }
        })
      );
    });

    test('should parse i18n reason_user JSON format', async () => {
      const params = {
        ...validParams,
        reason_user: '{"en":"Additional auth required","es":"Autenticación adicional requerida"}'
      };

      await script.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change': expect.objectContaining({
              reason_user: {
                en: 'Additional auth required',
                es: 'Autenticación adicional requerida'
              }
            })
          }
        })
      );
    });

    test('should throw error for invalid subject JSON', async () => {
      const params = {
        ...validParams,
        subject: 'invalid json'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });

    test('should include auth token in request', async () => {
      await script.invoke(validParams, mockContext);

      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'User-Agent': 'SGNL-CAEP-Hub/2.0'
          })
        })
      );
    });

    test('should use address from params when provided', async () => {
      const params = {
        ...validParams,
        address: 'https://custom.example.com/events'
      };

      await script.invoke(params, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(params, mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://custom.example.com/events',
        expect.any(Object)
      );
    });

    test('should use ADDRESS from environment when params.address not provided', async () => {
      await script.invoke(validParams, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(validParams, mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should handle non-retryable HTTP errors', async () => {
      transmitSET.mockResolvedValue({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });
    });

    test('should throw error for retryable HTTP errors', async () => {
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 429 Too Many Requests')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    test('should transmit JWT to correct URL', async () => {
      await script.invoke(validParams, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });
  });

  describe('error handler', () => {
    test('should request retry for 429 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 502 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 503 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 504 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('Authentication failed: 401 Unauthorized')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Authentication failed: 401 Unauthorized');
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, {});

      expect(result).toEqual({ status: 'halted' });
    });
  });
});
