"use client"

import type React from "react"

import { useState } from "react"
import { AlertCircle, CheckCircle, Loader2, Shield, ShieldAlert } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { detectPhishing } from "@/lib/phishing-detection"

type DetectionResult = {
  isSafe: boolean
  confidence: number
  modelResults: {
    randomForest: boolean
    svm: boolean
    logisticRegression: boolean
  }
  features: Record<string, any>
}

export function PhishingDetector() {
  const [url, setUrl] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<DetectionResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!url) {
      setError("Please enter a URL")
      return
    }

    try {
      setIsLoading(true)
      setError(null)

      // Validate URL format
      let urlToCheck = url
      if (!url.startsWith("http://") && !url.startsWith("https://")) {
        urlToCheck = "https://" + url
      }

      try {
        new URL(urlToCheck)
      } catch (e) {
        setError("Please enter a valid URL")
        setIsLoading(false)
        return
      }

      // Call the detection function
      const detectionResult = await detectPhishing(urlToCheck)
      setResult(detectionResult)
    } catch (err) {
      setError("An error occurred while analyzing the URL. Please try again.")
      console.error(err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          URL Analysis
        </CardTitle>
        <CardDescription>Enter a URL to check if it's legitimate or potentially malicious.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url">URL to check</Label>
            <div className="flex gap-2">
              <Input
                id="url"
                placeholder="Enter a URL (e.g., example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1"
              />
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Analyzing
                  </>
                ) : (
                  "Analyze"
                )}
              </Button>
            </div>
          </div>
        </form>

        {error && (
          <Alert variant="destructive" className="mt-4">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {result && (
          <div className="mt-6 space-y-4">
            <Alert variant={result.isSafe ? "default" : "destructive"}>
              {result.isSafe ? <CheckCircle className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
              <AlertTitle>{result.isSafe ? "Safe URL Detected" : "Potential Phishing Detected"}</AlertTitle>
              <AlertDescription>
                {result.isSafe
                  ? "This URL appears to be legitimate based on our analysis."
                  : "This URL shows characteristics commonly associated with phishing attempts."}
              </AlertDescription>
            </Alert>

            <Tabs defaultValue="summary">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="summary">Summary</TabsTrigger>
                <TabsTrigger value="models">Model Results</TabsTrigger>
                <TabsTrigger value="features">URL Features</TabsTrigger>
              </TabsList>

              <TabsContent value="summary" className="space-y-4">
                <div className="mt-2">
                  <div className="flex items-center justify-between py-2">
                    <span className="font-medium">Confidence Score:</span>
                    <div className="flex items-center">
                      <span className={result.isSafe ? "text-green-600" : "text-red-600"}>
                        {Math.round(result.confidence * 100)}%
                      </span>
                      <div className="ml-2 h-2 w-24 rounded-full bg-slate-200">
                        <div
                          className={`h-full rounded-full ${result.isSafe ? "bg-green-500" : "bg-red-500"}`}
                          style={{ width: `${Math.round(result.confidence * 100)}%` }}
                        />
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="font-medium">URL:</span>
                    <span className="text-slate-600 dark:text-slate-400 truncate max-w-[250px]">{url}</span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="font-medium">Analysis Date:</span>
                    <span className="text-slate-600 dark:text-slate-400">{new Date().toLocaleString()}</span>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="models">
                <div className="space-y-2 mt-2">
                  <div className="flex items-center justify-between py-2 border-b">
                    <span className="font-medium">Random Forest:</span>
                    <Badge variant={result.modelResults.randomForest ? "destructive" : "success"}>
                      {result.modelResults.randomForest ? "Phishing" : "Safe"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between py-2 border-b">
                    <span className="font-medium">Support Vector Machine:</span>
                    <Badge variant={result.modelResults.svm ? "destructive" : "success"}>
                      {result.modelResults.svm ? "Phishing" : "Safe"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="font-medium">Logistic Regression:</span>
                    <Badge variant={result.modelResults.logisticRegression ? "destructive" : "success"}>
                      {result.modelResults.logisticRegression ? "Phishing" : "Safe"}
                    </Badge>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="features">
                <div className="mt-2 space-y-2">
                  {result.features &&
                    Object.entries(result.features).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between py-2 border-b">
                        <span className="font-medium">
                          {key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase())}:
                        </span>
                        <span className="text-slate-600 dark:text-slate-400">
                          {typeof value === "boolean" ? (value ? "Yes" : "No") : value.toString()}
                        </span>
                      </div>
                    ))}
                </div>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </CardContent>
      <CardFooter className="flex justify-between">
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Powered by ML models: Random Forest, SVM, and Logistic Regression
        </p>
      </CardFooter>
    </Card>
  )
}
