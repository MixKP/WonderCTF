<script setup lang="ts">
import { ref } from 'vue'
import { useChallengesStore } from '@/stores/challenges'
import { apiErrorMessage } from '@/api/client'

const props = defineProps<{ challengeId: string; alreadySolved: boolean }>()

const store = useChallengesStore()
const flag = ref('')
const submitting = ref(false)
const result = ref<'correct' | 'incorrect' | null>(null)
const errorMessage = ref('')

async function handleSubmit() {
  errorMessage.value = ''
  result.value = null
  submitting.value = true
  try {
    const res = await store.submitFlag(props.challengeId, flag.value)
    result.value = res.correct ? 'correct' : 'incorrect'
    if (res.correct) flag.value = ''
  } catch (err) {
    errorMessage.value = apiErrorMessage(err, 'Could not submit flag')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="rounded-lg border border-ctf-border bg-ctf-panel p-4">
    <h2 class="mb-3 text-sm font-semibold uppercase tracking-wide text-gray-400">Submit flag</h2>

    <form class="flex gap-2" @submit.prevent="handleSubmit">
      <input
        v-model="flag"
        type="text"
        placeholder="CTF{...}"
        required
        :disabled="alreadySolved"
        class="flex-1 rounded border border-ctf-border bg-ctf-bg px-3 py-2 font-mono text-sm text-white focus:border-ctf-accent focus:outline-none disabled:opacity-50"
      />
      <button
        type="submit"
        :disabled="submitting || alreadySolved"
        class="rounded bg-ctf-accent-dim px-4 py-2 text-sm font-medium text-white hover:bg-ctf-accent hover:text-ctf-bg disabled:opacity-50"
      >
        {{ alreadySolved ? 'Solved' : submitting ? 'Checking…' : 'Submit' }}
      </button>
    </form>

    <p v-if="result === 'correct'" class="mt-2 text-sm text-emerald-400">Correct — points awarded.</p>
    <p v-else-if="result === 'incorrect'" class="mt-2 text-sm text-red-400">Not quite. Try again.</p>
    <p v-if="errorMessage" class="mt-2 text-sm text-red-400">{{ errorMessage }}</p>
  </div>
</template>
