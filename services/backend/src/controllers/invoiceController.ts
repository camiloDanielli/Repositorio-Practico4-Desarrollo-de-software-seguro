import { Request, Response, NextFunction } from 'express';
import InvoiceService from '../services/invoiceService';
import { Invoice } from '../types/invoice';

// Whitelists para validaciones
const ALLOWED_PAYMENT_BRANDS = ['visa', 'mastercard', 'amex']; 
const ALLOWED_OPERATORS = ['=', '==', '!=', 'eq', 'ne'];
const ALLOWED_STATUSES = ['paid', 'unpaid', 'pending'];

// Middleware helper: validación básica de UUID o ID numérico
function isValidId(id: string) {
  return /^[a-f0-9-]{6,64}$/i.test(id) || /^[0-9]+$/.test(id);
}

const listInvoices = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const status = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;
    const id = (req as any).user?.id;

    // Validar id del usuario
    if (!id || !isValidId(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Validar inputs
    if (status && !ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }
    if (operator && !ALLOWED_OPERATORS.includes(operator)) {
      return res.status(400).json({ error: 'Invalid operator value' });
    }

    const invoices = await InvoiceService.list(id, status, operator);
    res.json(invoices);
  } catch (err) {
    console.error('Error in listInvoices:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const setPaymentCard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const { paymentBrand, ccNumber, ccv, expirationDate } = req.body;
    const id = (req as any).user?.id;

    // Validar todos los campos
    if (!invoiceId || !isValidId(invoiceId)) {
      return res.status(400).json({ error: 'Invalid invoice ID' });
    }
    if (!id || !isValidId(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    if (!paymentBrand || !ALLOWED_PAYMENT_BRANDS.includes(paymentBrand)) {
      return res.status(400).json({ error: 'Invalid payment brand' });
    }
    if (!ccNumber || !/^[0-9]{13,19}$/.test(ccNumber)) {
      return res.status(400).json({ error: 'Invalid card number' });
    }
    if (!ccv || !/^[0-9]{3,4}$/.test(ccv)) {
      return res.status(400).json({ error: 'Invalid CCV' });
    }
    if (!expirationDate || !/^\d{2}\/\d{2}$/.test(expirationDate)) {
      return res.status(400).json({ error: 'Invalid expiration date format (MM/YY)' });
    }

    await InvoiceService.setPaymentCard(
      id,
      invoiceId,
      paymentBrand,
      ccNumber,
      ccv,
      expirationDate
    );

    res.status(200).json({ message: 'Payment successful' });
  } catch (err) {
    console.error('Error in setPaymentCard:', err);
    res.status(502).json({ error: 'Payment gateway error' });
  }
};

const getInvoicePDF = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const pdfName = req.query.pdfName as string | undefined;

    if (!invoiceId || !isValidId(invoiceId)) {
      return res.status(400).json({ error: 'Invalid invoice ID' });
    }
    if (!pdfName || !/^[\w,\s-]+\.(pdf)$/i.test(pdfName)) {
      return res.status(400).json({ error: 'Invalid pdfName parameter' });
    }

    const pdf = await InvoiceService.getReceipt(invoiceId, pdfName);
    res.setHeader('Content-Type', 'application/pdf');
    res.send(pdf);
  } catch (err) {
    console.error('Error in getInvoicePDF:', err);
    res.status(404).json({ error: 'Receipt not found' });
  }
};

const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;

    if (!invoiceId || !isValidId(invoiceId)) {
      return res.status(400).json({ error: 'Invalid invoice ID' });
    }

    const invoice = await InvoiceService.getInvoice(invoiceId);
    res.status(200).json(invoice);
  } catch (err) {
    console.error('Error in getInvoice:', err);
    res.status(404).json({ error: 'Invoice not found' });
  }
};

export default {
  listInvoices,
  setPaymentCard,
  getInvoice,
  getInvoicePDF
};
