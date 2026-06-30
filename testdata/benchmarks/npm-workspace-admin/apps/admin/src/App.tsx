import { QueryClient } from "@tanstack/react-query";
import { z } from "zod";
import React from "react";

const schema = z.object({ name: z.string() });
export function App() {
  const client = new QueryClient();
  return React.createElement("main", null, schema.parse({ name: "admin" }).name + client.isFetching());
}
