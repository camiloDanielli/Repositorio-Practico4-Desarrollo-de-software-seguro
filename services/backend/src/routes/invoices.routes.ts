import { Router } from 'express';
import routes from '../controllers/invoiceController';
import authenticateJWT from '../middleware/auth.middleware';

const router = Router();

// GET /invoices
router.get('/', authenticateJWT, routes.listInvoices);

// GET /invoices
router.get('/:id', authenticateJWT, routes.getInvoice);

// POST /invoices/:id/pay
router.post('/:id/pay', authenticateJWT, routes.setPaymentCard);
router.get('/:id/invoice', authenticateJWT, routes.getInvoicePDF);

export default router;