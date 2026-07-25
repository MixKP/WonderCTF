import { defineStore } from 'pinia'
import { ref } from 'vue'
import apiClient from '@/api/client'
import type { Challenge, SubmitFlagResponse } from '@/types'

export const useChallengesStore = defineStore('challenges', () => {
  const challenges = ref<Challenge[]>([])
  const loading = ref(false)

  async function fetchChallenges() {
    loading.value = true
    try {
      const { data } = await apiClient.get<Challenge[]>('/api/challenges')
      challenges.value = data
    } finally {
      loading.value = false
    }
  }

  async function fetchChallenge(id: string): Promise<Challenge> {
    const existing = challenges.value.find((c) => c.id === id)
    if (existing) return existing

    const { data } = await apiClient.get<Challenge>(`/api/challenges/${id}`)
    challenges.value.push(data)
    return data
  }

  async function submitFlag(challengeId: string, flag: string): Promise<SubmitFlagResponse> {
    const { data } = await apiClient.post<SubmitFlagResponse>('/api/submissions', {
      challengeId,
      flag,
    })
    if (data.correct) {
      const ch = challenges.value.find((c) => c.id === challengeId)
      if (ch) ch.solved = true
    }
    return data
  }

  return { challenges, loading, fetchChallenges, fetchChallenge, submitFlag }
})
