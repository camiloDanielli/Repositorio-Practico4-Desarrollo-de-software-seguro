/**
 * PRUEBAS DE SEGURIDAD - TEMPLATE INJECTION
 * Práctica 4 - Desarrollo de Software Seguro
 *
 * VULNERABILIDAD:
 * Template Injection en el envío de correos al crear usuario.
 * Los campos first_name y last_name se insertan directamente en el template HTML
 * sin sanitización, permitiendo inyección de código XSS.
 *
 * UBICACIÓN: src/services/authService.ts - método createUser()
 *
 * MITIGACIÓN ESPERADA:
 * Escapar caracteres HTML especiales (<, >, &, ", ') antes de insertarlos en el template.
 *
 * COMPORTAMIENTO:
 * - Branch main: Tests FALLAN (vulnerabilidad presente)
 * - Branch practico-2: Tests PASAN (vulnerabilidad mitigada)
 */

import nodemailer from "nodemailer";
import AuthService from "../../src/services/authService";
import db from "../../src/db";
import { User } from "../../src/types/user";

jest.mock("../../src/db");
const mockedDb = db as jest.MockedFunction<typeof db>;

jest.mock("nodemailer");
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

describe("Security: Template Injection in Email", () => {
  let mockSendMail: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock sendMail para capturar el HTML enviado
    mockSendMail = jest.fn().mockResolvedValue({ success: true });
    mockedNodemailer.createTransport.mockReturnValue({
      sendMail: mockSendMail,
    } as any);

    // Mock DB - usuario no existe (permite creación)
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };

    const insertChain = {
      returning: jest.fn().mockResolvedValue([{ id: "test-id" }]),
      insert: jest.fn().mockReturnThis(),
    };

    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);
  });

  /**
   * TEST 1: Script tag en first_name
   */
  it("debe escapar tags <script> en first_name", async () => {
    const maliciousUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: "<script>alert('Hackeado')</script>",
      last_name: "Normal",
    };

    await AuthService.createUser(maliciousUser);

    expect(mockSendMail).toHaveBeenCalledTimes(1);
    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    // FAIL en main: El script NO debe estar sin escapar
    expect(emailHtml).not.toContain("<script>alert('Hackeado')</script>");

    // PASS en practico-2: Debe estar escapado
    expect(emailHtml).toMatch(/(&lt;script&gt;|&#60;script&#62;)/i);
  });

  /**
   * TEST 2: Script tag en last_name
   */
  it("debe escapar tags <script> en last_name", async () => {
    const maliciousUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: "Normal",
      last_name: "<script>document.location='http://evil.com'</script>",
    };

    await AuthService.createUser(maliciousUser);

    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    expect(emailHtml).not.toContain("<script>document.location");
    expect(emailHtml).toMatch(/(&lt;script&gt;|&#60;script&#62;)/i);
  });

  /**
   * TEST 3: Event handlers (onerror)
   */
  it("debe escapar event handlers HTML", async () => {
    const maliciousUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: "<img src=x onerror=\"alert('XSS')\">",
      last_name: "Test",
    };

    await AuthService.createUser(maliciousUser);

    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    expect(emailHtml).not.toContain("<img src=x onerror=");
    expect(emailHtml).not.toContain("onerror=");
    expect(emailHtml).toMatch(/(&lt;img|&#60;img)/i);
  });

  /**
   * TEST 4: Tags iframe
   */
  it("debe escapar tags <iframe>", async () => {
    const maliciousUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: "<iframe src=\"javascript:alert('XSS')\"></iframe>",
      last_name: "Test",
    };

    await AuthService.createUser(maliciousUser);

    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    expect(emailHtml).not.toContain("<iframe src=");
    expect(emailHtml).toMatch(/(&lt;iframe|&#60;iframe)/i);
  });

  /**
   * TEST 5: Múltiples vectores de ataque
   */
  it("debe escapar múltiples vectores XSS", async () => {
    const maliciousUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: '<div onload="alert(1)">Test</div>',
      last_name: '<svg/onload=alert("XSS")>',
    };

    await AuthService.createUser(maliciousUser);

    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    // No debe haber event handlers sin escapar
    expect(emailHtml).not.toMatch(/<\w+[^>]*on\w+\s*=/i);
    expect(emailHtml).not.toContain("<div onload=");
    expect(emailHtml).not.toContain("<svg/onload=");
  });

  /**
   * TEST 6: Nombres legítimos (caso positivo)
   */
  it("debe preservar nombres legítimos correctamente", async () => {
    const validUser: User = {
      username: `testuser${Date.now()}`,
      password: "Pass123!",
      email: `test${Date.now()}@example.com`,
      first_name: "María José",
      last_name: "O'Connor-Smith",
    };

    await AuthService.createUser(validUser);

    const emailHtml: string = mockSendMail.mock.calls[0][0].html;

    // Nombres deben aparecer (pueden estar escaped si tienen chars especiales)
    expect(emailHtml).toMatch(/María|Mar.*a/);
    expect(emailHtml).toMatch(/Connor/);

    // No debe contener scripts maliciosos
    expect(emailHtml).not.toContain("<script>");
  });
});
