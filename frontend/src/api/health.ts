export type Health = { status: string; database?: string };

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8001";

export async function getHealth(): Promise<Health> {
  const response = await fetch(`${apiBaseUrl}/health/ready`);
  if (!response.ok) throw new Error(`Health check failed (${response.status})`);
  return response.json() as Promise<Health>;
}
