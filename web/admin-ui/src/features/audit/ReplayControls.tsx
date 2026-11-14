import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";

// The controls of a replay, under its frame (ADR-0088): play or pause, step, position, speed, and
// where the recording stands. The screen owns the state; this shows it and reports a gesture.
export function ReplayControls({
  playing,
  position,
  speed,
  loaded,
  sequence,
  at,
  endText,
  onPlay,
  onStep,
  onSeek,
  onSpeed,
}: {
  playing: boolean;
  position: number;
  speed: number;
  loaded: number;
  sequence: number;
  at: Date;
  endText: string;
  onPlay: () => void;
  onStep: (delta: -1 | 1) => void;
  onSeek: (position: number) => void;
  onSpeed: (speed: number) => void;
}) {
  const { t, i18n } = useAppTranslation();
  return (
    <>
      <div className="ob-form-actions replay-controls">
        <Button variant="primary" onClick={onPlay}>
          {playing ? t("replay.pause") : t("replay.play")}
        </Button>
        <Button disabled={position === 0} onClick={() => onStep(-1)}>
          {t("replay.previousFrame")}
        </Button>
        <Button disabled={position >= loaded - 1} onClick={() => onStep(1)}>
          {t("replay.nextFrame")}
        </Button>
        <label>
          {t("replay.position")}
          <input type="range" min={0} max={loaded - 1} value={position} onChange={(e) => onSeek(Number(e.target.value))} />
        </label>
        <label>
          {t("replay.speed")}
          <select value={speed} onChange={(e) => onSpeed(Number(e.target.value))}>
            <option value={1}>×1</option>
            <option value={2}>×2</option>
            <option value={4}>×4</option>
          </select>
        </label>
      </div>
      <p className="ob-hint" role="status">
        {t("replay.status", { sequence, position: position + 1, loaded })}{" "}
        <time dateTime={at.toISOString()}>{at.toLocaleString(i18n.language)}</time>. {endText}
      </p>
    </>
  );
}
