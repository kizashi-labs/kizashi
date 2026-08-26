'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

export interface FavoriteItem {
  href: string
  label: string
}

const QUERY_KEY = ['user-favorites']
const MAX_FAVORITES = 20

async function fetchFavorites(): Promise<FavoriteItem[]> {
  const data = await apiFetch<{ favorites: FavoriteItem[] }>('/api/v1/user/favorites')
  return data.favorites ?? []
}

async function saveFavorites(items: FavoriteItem[]): Promise<FavoriteItem[]> {
  const data = await apiFetch<{ favorites: FavoriteItem[] }>('/api/v1/user/favorites', {
    method: 'PUT',
    body: JSON.stringify({ favorites: items }),
  })
  return data.favorites ?? []
}

export function useFavorites() {
  const queryClient = useQueryClient()

  const { data: favorites = [] } = useQuery<FavoriteItem[]>({
    queryKey: QUERY_KEY,
    queryFn: fetchFavorites,
    staleTime: 60_000,
  })

  const mutation = useMutation({
    mutationFn: saveFavorites,
    onMutate: async (next) => {
      await queryClient.cancelQueries({ queryKey: QUERY_KEY })
      const prev = queryClient.getQueryData<FavoriteItem[]>(QUERY_KEY)
      queryClient.setQueryData(QUERY_KEY, next)
      return { prev }
    },
    onError: (_err, _next, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(QUERY_KEY, ctx.prev)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: QUERY_KEY })
    },
  })

  const isFavorite = (href: string) => favorites.some(f => f.href === href)

  const addFavorite = (href: string, label: string) => {
    if (isFavorite(href)) return
    const next = [...favorites, { href, label }].slice(0, MAX_FAVORITES)
    mutation.mutate(next)
  }

  const removeFavorite = (href: string) => {
    const next = favorites.filter(f => f.href !== href)
    mutation.mutate(next)
  }

  const toggleFavorite = (href: string, label: string) => {
    if (isFavorite(href)) {
      removeFavorite(href)
    } else {
      addFavorite(href, label)
    }
  }

  return { favorites, isFavorite, addFavorite, removeFavorite, toggleFavorite }
}
