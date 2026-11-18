import { useAppTranslation } from "../i18n";

// The pagination line of the reference tables: the range shown, then numbered pages around the
// current one. It pages exactly what the API pages — the screen never claims a complete list.
function pageWindow(page: number, pageCount: number): (number | "gap")[] {
  if (pageCount <= 5) return Array.from({ length: pageCount }, (_, index) => index + 1);
  const start = Math.min(Math.max(page - 1, 1), pageCount - 2);
  const window = [1, start, start + 1, pageCount].filter((value, index, all) => all.indexOf(value) === index);
  const result: (number | "gap")[] = [];
  window.forEach((value, index) => {
    if (index > 0 && value - window[index - 1] > 1) result.push("gap");
    result.push(value);
  });
  return result;
}

export function ReferencePager({
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
  const { t } = useAppTranslation();
  const pageCount = Math.max(1, Math.ceil(totalItems / pageSize));
  const first = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, totalItems);
  return (
    <div className="reference-table-footer">
      <p className="reference-table-range">
        {totalItems === 0
          ? t("common.pager.empty", { noun })
          : t("common.pager.range", { first, last, total: totalItems, noun })}
      </p>
      <nav className="reference-pager" aria-label={t("common.pager.aria")}>
        <button type="button" aria-label={t("common.pager.previous")} disabled={page <= 1} onClick={() => onPage(page - 1)}>
          ‹
        </button>
        {pageWindow(page, pageCount).map((entry, index) => entry === "gap"
          ? <span key={`gap-${index}`} className="reference-pager-gap" aria-hidden="true">…</span>
          : (
            <button
              key={entry}
              type="button"
              aria-label={t("common.pager.page", { page: entry })}
              aria-current={entry === page ? "page" : undefined}
              onClick={() => onPage(entry)}
            >
              {entry}
            </button>
          ))}
        <button type="button" aria-label={t("common.pager.next")} disabled={page >= pageCount} onClick={() => onPage(page + 1)}>
          ›
        </button>
      </nav>
    </div>
  );
}
