import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import apiClient from '@/api/client'
import type { AuthResponse } from '@/types'

const STORAGE_KEY = 'ctf_auth'

interface StoredAuth {
  token: string
  userId: string
  username: string
  isAdmin: boolean
}

function loadStoredAuth(): StoredAuth | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as StoredAuth
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const stored = loadStoredAuth()

  const token = ref<string | null>(stored?.token ?? null)
  const userId = ref<string | null>(stored?.userId ?? null)
  const username = ref<string | null>(stored?.username ?? null)
  const isAdmin = ref(stored?.isAdmin ?? false)

  const isAuthenticated = computed(() => token.value !== null)

  function setAuth(auth: AuthResponse) {
    token.value = auth.token
    userId.value = auth.userId
    username.value = auth.username
    isAdmin.value = auth.isAdmin
    sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        token: auth.token,
        userId: auth.userId,
        username: auth.username,
        isAdmin: auth.isAdmin,
      }),
    )
  }

  function logout() {
    token.value = null
    userId.value = null
    username.value = null
    isAdmin.value = false
    sessionStorage.removeItem(STORAGE_KEY)
  }

  async function login(usernameInput: string, password: string) {
    const { data } = await apiClient.post<AuthResponse>('/api/auth/login', {
      username: usernameInput,
      password,
    })
    setAuth(data)
  }

  async function register(usernameInput: string, email: string, password: string) {
    const { data } = await apiClient.post<AuthResponse>('/api/auth/register', {
      username: usernameInput,
      email,
      password,
    })
    setAuth(data)
  }

  return { token, userId, username, isAdmin, isAuthenticated, login, register, logout }
})
