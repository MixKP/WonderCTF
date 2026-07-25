CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE challenges (
    id          TEXT PRIMARY KEY,        -- slug, e.g. 'a01-broken-access-control'
    category    TEXT NOT NULL,           -- e.g. 'A01: Broken Access Control'
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    points      INTEGER NOT NULL CHECK (points > 0),
    url         TEXT NOT NULL,           -- where the player reaches the live challenge
    flag_hash   TEXT NOT NULL,           -- bcrypt hash of the expected flag
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE submissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    correct      BOOLEAN NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_submissions_user ON submissions(user_id);
CREATE INDEX idx_submissions_challenge ON submissions(challenge_id);

-- A user is credited for a challenge exactly once: the first correct submission.
CREATE UNIQUE INDEX uniq_first_solve ON submissions(user_id, challenge_id) WHERE correct;

CREATE VIEW scoreboard AS
SELECT
    u.id AS user_id,
    u.username,
    COALESCE(SUM(c.points), 0) AS score,
    COUNT(s.id) AS solved_count,
    MAX(s.submitted_at) AS last_solve_at
FROM users u
LEFT JOIN submissions s ON s.user_id = u.id AND s.correct
LEFT JOIN challenges c ON c.id = s.challenge_id
GROUP BY u.id, u.username
ORDER BY score DESC, last_solve_at ASC NULLS LAST;
