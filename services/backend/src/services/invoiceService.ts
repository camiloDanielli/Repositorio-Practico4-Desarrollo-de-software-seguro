// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

class InvoiceService {
  /**
   * Lista facturas de un usuario con filtros opcionales
   * ✅ MITIGACIÓN SQL INJECTION: Validación de inputs y consultas parametrizadas
   */
  static async list(userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    // Listas blancas
    const allowedStatuses = ['paid', 'unpaid', 'pending'];

    // 🔒 Validación del operador con expresión regular (solo símbolos seguros)
    if (operator && !/^(=|==|!=|eq|ne)$/.test(operator.trim())) {
      const err: any = new Error('Invalid operator');
      err.statusCode = 400;
      throw err;
    }

    // 🔒 Validación del estado (solo valores permitidos)
    if (status && !allowedStatuses.includes(status)) {
      const err: any = new Error('Invalid status');
      err.statusCode = 400;
      throw err;
    }

    // 🔒 Validar formato del estado (evita inyecciones por caracteres especiales)
    if (status && !/^[a-z]+$/i.test(status)) {
      const err: any = new Error('Invalid status format');
      err.statusCode = 400;
      throw err;
    }

    // Normalizar operador a formato SQL válido
    const opMap: Record<string, string> = {
      '=': '=',
      '==': '=',
      'eq': '=',
      '!=': '!=',
      'ne': '!='
    };
    const normalizedOperator = operator ? opMap[operator.trim()] || '=' : '=';

    // Construcción segura de consulta con Knex (usa parametrización automática)
    let q = db<InvoiceRow>('invoices').where({ userId });

    if (status) {
      q = q.where('status', normalizedOperator, status);
    }

    const rows = await q.select();

    return rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status
    }));
  }

  /**
   * Asigna una tarjeta de pago y actualiza la factura como pagada
   */
  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
      ccNumber,
      ccv,
      expirationDate
    });

    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });
  }

  /**
   * Obtiene una factura por ID
   * ✅ MITIGACIÓN SQL INJECTION: Knex usa consultas parametrizadas por defecto
   */
  static async getInvoice(invoiceId: string): Promise<Invoice> {
    if (!invoiceId || typeof invoiceId !== 'string' || /[^a-zA-Z0-9_-]/.test(invoiceId)) {
      const err: any = new Error('Invalid invoice ID');
      err.statusCode = 400;
      throw err;
    }

    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();

    if (!invoice) {
      const err: any = new Error('Invoice not found');
      err.statusCode = 404;
      throw err;
    }

    return invoice as Invoice;
  }

  /**
   * Retorna el recibo PDF de una factura si existe
   */
  static async getReceipt(invoiceId: string, pdfName: string) {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      const err: any = new Error('Invoice not found');
      err.statusCode = 404;
      throw err;
    }

    try {
      // 🔒 Normalización del nombre del archivo (previene path traversal)
      const safeName = path.basename(pdfName);
      const filePath = path.join('/invoices', safeName);
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      console.error('Error reading receipt file:', error);
      const err: any = new Error('Receipt not found');
      err.statusCode = 404;
      throw err;
    }
  }
}

export default InvoiceService;