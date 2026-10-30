import { createContext, useContext } from "react";
import { Api, TokenClaims } from "./api";

export interface SignedIn {
  api: Api;
  who: TokenClaims | null;
  signOut: () => void;
}

export const SignedInContext = createContext<SignedIn | null>(null);

export function useSignedIn(): SignedIn {
  const v = useContext(SignedInContext);
  if (!v) throw new Error("useSignedIn outside a signed-in page");
  return v;
}
