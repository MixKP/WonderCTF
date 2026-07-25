export interface AuthResponse {
  token: string
  userId: string
  username: string
  isAdmin: boolean
}

export interface Challenge {
  id: string
  category: string
  title: string
  description: string
  points: number
  url: string
  solved: boolean
}

export interface SubmitFlagResponse {
  correct: boolean
  alreadySolved: boolean
  pointsAwarded: number
}

export interface ScoreboardEntry {
  userId: string
  username: string
  score: number
  solvedCount: number
  lastSolveAt?: string
}

export interface ApiError {
  error: string
}
