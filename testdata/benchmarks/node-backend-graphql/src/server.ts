import { ApolloServer } from "@apollo/server";
import express from "express";
import cors from "cors";
import { GraphQLSchema } from "graphql";

const app = express();
app.use(cors());
const server = new ApolloServer({ schema: new GraphQLSchema({}) });
void server.start().then(() => app.listen(4000));
