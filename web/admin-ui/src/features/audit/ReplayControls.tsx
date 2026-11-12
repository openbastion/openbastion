import { Button } from "../../shared/ui/Button";

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
  return (
    <>
      <div className="ob-form-actions replay-controls">
        <Button variant="primary" onClick={onPlay}>
          {playing ? "Pause" : "Lire"}
        </Button>
        <Button disabled={position === 0} onClick={() => onStep(-1)}>
          Image précédente
        </Button>
        <Button disabled={position >= loaded - 1} onClick={() => onStep(1)}>
          Image suivante
        </Button>
        <label>
          Position
          <input type="range" min={0} max={loaded - 1} value={position} onChange={(e) => onSeek(Number(e.target.value))} />
        </label>
        <label>
          Vitesse
          <select value={speed} onChange={(e) => onSpeed(Number(e.target.value))}>
            <option value={1}>×1</option>
            <option value={2}>×2</option>
            <option value={4}>×4</option>
          </select>
        </label>
      </div>
      <p className="ob-hint" role="status">
        Image {sequence} ({position + 1} sur {loaded} chargées), enregistrée le{" "}
        <time dateTime={at.toISOString()}>{at.toLocaleString("fr-FR")}</time>. {endText}
      </p>
    </>
  );
}
