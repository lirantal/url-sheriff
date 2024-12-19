export async function sheriff(url: string): Promise<boolean> {

  if (url.includes('localhost')) {
    throw new Error('URL uses a host set to a localhost IP')
  }

  return true;
}