import { Button } from "./Button";

// The one pager of the UI: the API pages every list it gives, and a screen that shows one page
// shows this. `noun` is the counted thing, already in French ("compte(s)", "commande(s)").
export function Pager({
  page,
  pageSize,
  totalItems,
  noun,
  onPage,
}: {
  page: number;
  pageSize: number;
  totalItems: number;
  noun: string;
  onPage: (page: number) => void;
}) {
  return (
    <p className="ob-pager">
      <Button disabled={page <= 1} onClick={() => onPage(page - 1)}>
        Précédent
      </Button>
      <span>
        page {page} — {totalItems} {noun}
      </span>
      <Button disabled={page * pageSize >= totalItems} onClick={() => onPage(page + 1)}>
        Suivant
      </Button>
    </p>
  );
}
