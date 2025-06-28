import type * as express from "express";
import type { User } from "../../entities/User";

// arquivo pra fazer o override da tipagem do next
declare global {
  namespace Express {
    interface Request {
      user: User;
    }
  }
}