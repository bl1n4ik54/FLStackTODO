import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

export const api = createApi({
  baseQuery: fetchBaseQuery({ baseUrl: 'http://localhost:5000' }),
  endpoints: (builder) => ({
    register: builder.mutation({
      query: (credentials) => ({
        url: '/register',
        method: 'POST',
        body: credentials,
      }),
    }),
    login: builder.mutation({
      query: (credentials) => ({
        url: '/login',
        method: 'POST',
        body: credentials,
      }),
    }),
    getTasks: builder.query({
      query: () => ({
        url: '/tasks',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      }),
    }),
    createTask: builder.mutation({
      query: (task) => ({
        url: '/tasks',
        method: 'POST',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
        body: task,
      }),
    }),
  }),
});

export const { useRegisterMutation, useLoginMutation, useGetTasksQuery, useCreateTaskMutation } = api;